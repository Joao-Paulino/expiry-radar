package main

import (
	"context"
	"encoding/pem"
	"github.com/Joao-Paulino/expiry-radar/internal/checker"
	awscheck "github.com/Joao-Paulino/expiry-radar/internal/checker/aws"
	"github.com/Joao-Paulino/expiry-radar/internal/checker/azure"
	"github.com/Joao-Paulino/expiry-radar/internal/checker/vault"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadConfig_ParsesValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	content := `{
        "collector_url": "https://collector.example.com",
        "token": "abc",
        "agent_id": "web-01",
        "queue_path": "/var/lib/expiry-radar/queue.jsonl",
        "interval_seconds": 3600,
        "tls_targets": [{"host": "mail.example.com", "port": 25, "start_tls": "smtp"}]
    }`
	os.WriteFile(path, []byte(content), 0600)

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.CollectorURL != "https://collector.example.com" || cfg.AgentID != "web-01" {
		t.Fatalf("got %+v", cfg)
	}
	if len(cfg.TLSTargets) != 1 || cfg.TLSTargets[0].StartTLS != "smtp" {
		t.Fatalf("got TLSTargets=%+v", cfg.TLSTargets)
	}
}

// TestConfig_Validate_RejectsMissingOrZeroFields proves a config with
// interval_seconds missing (or 0) is rejected up front: before, it
// reached time.NewTicker(0), which panics.
func TestConfig_Validate_RejectsMissingOrZeroFields(t *testing.T) {
	valid := Config{CollectorURL: "https://c", Token: "t", AgentID: "a", QueuePath: "/q", IntervalSeconds: 60}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	cases := map[string]func(c *Config){
		"zero interval":     func(c *Config) { c.IntervalSeconds = 0 },
		"negative interval": func(c *Config) { c.IntervalSeconds = -5 },
		"no collector url":  func(c *Config) { c.CollectorURL = "" },
		"no token":          func(c *Config) { c.Token = "" },
		"no agent id":       func(c *Config) { c.AgentID = "" },
		"no queue path":     func(c *Config) { c.QueuePath = "" },
	}
	for name, mutate := range cases {
		c := valid
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

// TestRun_ChecksImmediatelyAtStartup proves the agent pushes a first
// batch right away instead of waiting a whole interval (an hour, by
// the documented default) before reporting anything.
func TestRun_ChecksImmediatelyAtStartup(t *testing.T) {
	pushed := make(chan struct{}, 10)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pushed <- struct{}{}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	dir := t.TempDir()
	cfg := Config{
		CollectorURL:    srv.URL + "/ingest",
		CollectorCAFile: writeCAForTest(t, dir, srv),
		Token:           "t",
		AgentID:         "a",
		QueuePath:       filepath.Join(dir, "queue.jsonl"),
		IntervalSeconds: 3600,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg) }()

	select {
	case <-pushed:
	case <-time.After(15 * time.Second):
		t.Fatal("no batch pushed at startup; agent waited for the first tick")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run returned error: %v", err)
	}
}

// TestRun_TrustsSelfSignedCollectorViaCAFile proves an agent can push
// to a Collector using a self-signed certificate (allowed by the spec)
// once collector_ca_file points at that certificate. Before, the agent
// only trusted the system store, so this deployment could never work.
func TestRun_TrustsSelfSignedCollectorViaCAFile(t *testing.T) {
	pushed := make(chan struct{}, 10)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pushed <- struct{}{}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	dir := t.TempDir()
	caFile := writeCAForTest(t, dir, srv)

	cfg := Config{
		CollectorURL:    srv.URL + "/ingest",
		CollectorCAFile: caFile,
		Token:           "t",
		AgentID:         "a",
		QueuePath:       filepath.Join(dir, "queue.jsonl"),
		IntervalSeconds: 3600,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg) }()

	select {
	case <-pushed:
	case <-time.After(15 * time.Second):
		t.Fatal("agent never reached the self-signed collector")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run returned error: %v", err)
	}
}

// TestConfig_Validate_RejectsPlainHTTPCollector proves the agent
// refuses to send its bearer token over plain HTTP.
func TestConfig_Validate_RejectsPlainHTTPCollector(t *testing.T) {
	c := Config{CollectorURL: "http://collector.example.com", Token: "t", AgentID: "a", QueuePath: "/q", IntervalSeconds: 60}
	if err := c.Validate(); err == nil {
		t.Fatal("expected an error for a plain http:// collector_url")
	}
}

// writeCAForTest writes srv's self-signed certificate as a PEM CA file.
func writeCAForTest(t *testing.T, dir string, srv *httptest.Server) string {
	t.Helper()
	caFile := filepath.Join(dir, "collector-ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caFile, pemBytes, 0600); err != nil {
		t.Fatal(err)
	}
	return caFile
}

// TestCheckers_IncludesVaultWhenConfigured proves the vault section
// turns on the Vault checker, and an invalid one stops the agent.
func TestCheckers_IncludesVaultWhenConfigured(t *testing.T) {
	base := Config{CollectorURL: "https://c", Token: "t", AgentID: "a", QueuePath: "/q", IntervalSeconds: 60}
	if names := checkerNames(checkers(base)); names != "tls-checker" {
		t.Fatalf("without vault: %q", names)
	}
	withVault := base
	withVault.Vault = &vault.Config{Address: "https://vault:8200", Auth: vault.Auth{TokenFile: "/t"}, PKIMounts: []string{"pki"}}
	if err := withVault.Validate(); err != nil {
		t.Fatalf("valid vault config rejected: %v", err)
	}
	if names := checkerNames(checkers(withVault)); names != "tls-checker,vault" {
		t.Fatalf("with vault: %q", names)
	}
	withVault.Vault.Address = "http://vault:8200"
	if withVault.Validate() == nil {
		t.Fatal("invalid vault config accepted")
	}
}

// TestCheckers_IncludesAzureWhenConfigured proves the azure section
// turns on the Azure checker, and an invalid one stops the agent.
func TestCheckers_IncludesAzureWhenConfigured(t *testing.T) {
	cfg := Config{CollectorURL: "https://c", Token: "t", AgentID: "a", QueuePath: "/q", IntervalSeconds: 60,
		Azure: &azure.Config{Auth: "managed_identity", KeyVaults: []string{"kv-prod-weu"}}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid azure config rejected: %v", err)
	}
	if names := checkerNames(checkers(cfg)); names != "tls-checker,azure" {
		t.Fatalf("with azure: %q", names)
	}
	cfg.Azure.Auth = "password"
	if cfg.Validate() == nil {
		t.Fatal("invalid azure config accepted")
	}
}

func TestCheckers_IncludesAWSWhenConfigured(t *testing.T) {
	cfg := Config{CollectorURL: "https://c", Token: "t", AgentID: "a", QueuePath: "/q", IntervalSeconds: 60,
		AWS: &awscheck.Config{Auth: "instance_role", Regions: []string{"eu-west-1"}}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid aws config rejected: %v", err)
	}
	if names := checkerNames(checkers(cfg)); names != "tls-checker,aws" {
		t.Fatalf("with aws: %q", names)
	}
	cfg.AWS.Auth = "access_keys"
	if cfg.Validate() == nil {
		t.Fatal("static keys accepted")
	}
}

func checkerNames(cs []checker.Checker) string {
	var n []string
	for _, c := range cs {
		n = append(n, c.Name())
	}
	return strings.Join(n, ",")
}
