// Command agent runs the Expiry Radar Agent: it periodically runs the
// configured checkers and pushes results to the Collector, queueing
// locally if the Collector is unreachable.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/agent"
	"github.com/Joao-Paulino/expiry-radar/internal/checker"
	awscheck "github.com/Joao-Paulino/expiry-radar/internal/checker/aws"
	"github.com/Joao-Paulino/expiry-radar/internal/checker/azure"
	tlschecker "github.com/Joao-Paulino/expiry-radar/internal/checker/tls"
	"github.com/Joao-Paulino/expiry-radar/internal/checker/vault"
	"github.com/Joao-Paulino/expiry-radar/internal/logging"
)

// Config configures the agent binary, loaded from a JSON file given
// as the binary's only CLI argument.
type Config struct {
	CollectorURL string `json:"collector_url"`
	// CollectorCAFile, if set, is a PEM file of CA certificates the
	// agent trusts for the Collector in addition to the system store,
	// so a Collector using a self-signed certificate can be reached.
	CollectorCAFile string              `json:"collector_ca_file"`
	Token           string              `json:"token"`
	AgentID         string              `json:"agent_id"`
	QueuePath       string              `json:"queue_path"`
	TLSTargets      []tlschecker.Target `json:"tls_targets"`
	// Vault, if set, also checks a HashiCorp Vault (see README).
	Vault *vault.Config `json:"vault"`
	// Azure, if set, also checks Azure (see README).
	Azure *azure.Config `json:"azure"`
	// AWS, if set, also checks AWS (see README).
	AWS             *awscheck.Config `json:"aws"`
	IntervalSeconds int              `json:"interval_seconds"`
}

// loadConfig reads and decodes the JSON config file at path.
func loadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate reports the first missing or invalid required field, so a
// misconfigured agent fails fast at startup instead of panicking
// (time.NewTicker panics on a non-positive interval) or silently
// pushing nowhere.
func (c Config) Validate() error {
	if c.CollectorURL == "" {
		return fmt.Errorf("agent: collector_url is required")
	}
	if !strings.HasPrefix(strings.ToLower(c.CollectorURL), "https://") {
		return fmt.Errorf("agent: collector_url must use https:// (the agent token must never travel in plain text)")
	}
	if c.Token == "" {
		return fmt.Errorf("agent: token is required")
	}
	if c.AgentID == "" {
		return fmt.Errorf("agent: agent_id is required")
	}
	if c.QueuePath == "" {
		return fmt.Errorf("agent: queue_path is required")
	}
	if c.Vault != nil {
		if err := c.Vault.Validate(); err != nil {
			return err
		}
	}
	if c.Azure != nil {
		if err := c.Azure.Validate(); err != nil {
			return err
		}
	}
	if c.AWS != nil {
		if err := c.AWS.Validate(); err != nil {
			return err
		}
	}
	if c.IntervalSeconds <= 0 {
		return fmt.Errorf("agent: interval_seconds must be a positive number of seconds")
	}
	return nil
}

// trustCAFile adds the PEM certificates in path to the roots the
// pusher trusts for the Collector, on top of the system store.
func trustCAFile(p *agent.Pusher, path string) error {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("agent: reading collector_ca_file: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pemBytes) {
		return fmt.Errorf("agent: collector_ca_file contains no PEM certificates")
	}

	client := p.HTTPClient()
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport == nil {
		transport = http.DefaultTransport.(*http.Transport).Clone()
	} else {
		transport = transport.Clone()
	}
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	client.Transport = transport
	return nil
}

// checkers returns the checkers this agent runs: TLS always, Vault,
// Azure and AWS when configured.
func checkers(cfg Config) []checker.Checker {
	cs := []checker.Checker{tlschecker.New(cfg.TLSTargets)}
	if cfg.Vault != nil {
		cs = append(cs, vault.New(*cfg.Vault))
	}
	if cfg.Azure != nil {
		cs = append(cs, azure.New(*cfg.Azure))
	}
	if cfg.AWS != nil {
		cs = append(cs, awscheck.Checkers(*cfg.AWS)...)
	}
	return cs
}

// run validates cfg, runs one check immediately, then repeats every
// IntervalSeconds until ctx is cancelled.
func run(ctx context.Context, cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}

	pusher := agent.NewPusher(cfg.CollectorURL, cfg.Token)
	if cfg.CollectorCAFile != "" {
		if err := trustCAFile(pusher, cfg.CollectorCAFile); err != nil {
			return err
		}
	}

	runner := agent.NewRunner(
		cfg.AgentID,
		checkers(cfg),
		pusher,
		agent.NewQueue(cfg.QueuePath),
	)

	runOnce := func() {
		if err := runner.RunOnce(ctx); err != nil {
			log.Printf("agent: run once error: %s", logging.Sanitize(err.Error()))
		}
	}

	runOnce()

	ticker := time.NewTicker(time.Duration(cfg.IntervalSeconds) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			runOnce()
		case <-ctx.Done():
			return nil
		}
	}
}

func main() {
	if handleVersion(os.Args, os.Stdout) {
		return
	}
	if len(os.Args) < 2 {
		log.Fatal("usage: agent <config.json>")
	}

	cfg, err := loadConfig(os.Args[1])
	if err != nil {
		log.Printf("agent: loading config: %s", logging.Sanitize(err.Error()))
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, cfg); err != nil {
		log.Printf("agent: %s", logging.Sanitize(err.Error()))
		os.Exit(1)
	}
}
