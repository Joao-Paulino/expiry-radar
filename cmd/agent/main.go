// Command agent runs the Expiry Radar Agent: it periodically runs the
// configured checkers and pushes results to the Collector, queueing
// locally if the Collector is unreachable.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/agent"
	"github.com/Joao-Paulino/expiry-radar/internal/checker"
	tlschecker "github.com/Joao-Paulino/expiry-radar/internal/checker/tls"
	"github.com/Joao-Paulino/expiry-radar/internal/logging"
)

// Config configures the agent binary, loaded from a JSON file given
// as the binary's only CLI argument.
type Config struct {
	CollectorURL    string              `json:"collector_url"`
	Token           string              `json:"token"`
	AgentID         string              `json:"agent_id"`
	QueuePath       string              `json:"queue_path"`
	TLSTargets      []tlschecker.Target `json:"tls_targets"`
	IntervalSeconds int                 `json:"interval_seconds"`
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
	if c.Token == "" {
		return fmt.Errorf("agent: token is required")
	}
	if c.AgentID == "" {
		return fmt.Errorf("agent: agent_id is required")
	}
	if c.QueuePath == "" {
		return fmt.Errorf("agent: queue_path is required")
	}
	if c.IntervalSeconds <= 0 {
		return fmt.Errorf("agent: interval_seconds must be a positive number of seconds")
	}
	return nil
}

// run validates cfg, runs one check immediately, then repeats every
// IntervalSeconds until ctx is cancelled.
func run(ctx context.Context, cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}

	tlsChecker := tlschecker.New(cfg.TLSTargets)
	runner := agent.NewRunner(
		cfg.AgentID,
		[]checker.Checker{tlsChecker},
		agent.NewPusher(cfg.CollectorURL, cfg.Token),
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
