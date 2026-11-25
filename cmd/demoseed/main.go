// Command demoseed populates a fresh Collector database with
// realistic, clearly-fake example data across every checker kind
// (TLS certificates, Vault, Azure, AWS, GCP, VMware, FlexLM licences),
// so a freshly started demo collector shows a populated dashboard
// instead of an empty one. The demo also runs a real agent that
// live-checks a few other real public domains on top of this
// synthetic data (see deploy/demo/agent.json) — deliberately
// different hostnames from the ones seeded here.
//
// It is demo tooling only: it writes directly to the database through
// the same Store interface a real Agent's ingest batch would go
// through (store.SaveResult), under a synthetic agent ID, so the
// seeded rows behave exactly like real reports — including the
// "two clean runs without it and it's gone" rule — but it is never
// built into the collector/agent binaries and never runs in a real
// deployment.
//
// Usage: demoseed <collector.json>
// It exits 0 and does nothing if the database already has rows from
// the demo agent (so re-running the container doesn't duplicate data
// or push expiry dates further out on every restart).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/db"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/store"
)

const demoAgentID = "agent-demo"

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: demoseed <collector.json>")
		os.Exit(2)
	}
	cfg, err := loadConfig(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "demoseed: %s\n", err)
		os.Exit(1)
	}

	sqlDB, err := db.Open(cfg.DBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "demoseed: opening %s: %s\n", cfg.DBPath, err)
		os.Exit(1)
	}
	defer sqlDB.Close()

	s := store.NewSQLite(sqlDB)
	ctx := context.Background()

	// A real Agent touches itself on every batch it pushes, even a
	// repeat one, so the dashboard's "last seen" time for it stays
	// current rather than showing "unknown" (never touched) or a
	// stale timestamp from the demo container's first-ever start.
	if err := s.TouchAgent(ctx, demoAgentID); err != nil {
		fmt.Fprintf(os.Stderr, "demoseed: %s\n", err)
		os.Exit(1)
	}

	existing, err := s.ListCurrent(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "demoseed: %s\n", err)
		os.Exit(1)
	}
	for _, r := range existing {
		if r.ReportedBy == demoAgentID {
			fmt.Println("demoseed: already seeded, nothing to do")
			return
		}
	}

	now := time.Now().UTC()
	if err := seed(ctx, s, now); err != nil {
		fmt.Fprintf(os.Stderr, "demoseed: %s\n", err)
		os.Exit(1)
	}
	fmt.Println("demoseed: seeded example data for agent-demo")
}

type minimalConfig struct {
	DBPath string `json:"db_path"`
}

func loadConfig(path string) (minimalConfig, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is the operator's own config argument
	if err != nil {
		return minimalConfig{}, err
	}
	var c minimalConfig
	if err := json.Unmarshal(data, &c); err != nil {
		return minimalConfig{}, err
	}
	if c.DBPath == "" {
		return minimalConfig{}, fmt.Errorf("%s: db_path is required", path)
	}
	return c, nil
}

// checkerBatch is one checker's worth of records to save in one
// SaveResult call, exactly as a real Agent would push them.
type checkerBatch struct {
	checkerName string
	records     []checker.ExpiryRecord
}

func seed(ctx context.Context, s store.Store, now time.Time) error {
	d := func(days int) time.Time { return now.Add(time.Duration(days) * 24 * time.Hour) }

	batches := []checkerBatch{
		// Besides this synthetic batch, the demo also runs a real agent
		// that live-checks a few other real public domains (see
		// deploy/demo/agent.json) — deliberately different hostnames
		// from the ones below, so the two sources never collide.
		{checkerName: "tls", records: []checker.ExpiryRecord{
			{Source: "cloud.google.com:443", Name: "*.google.com", Kind: "certificate", ExpiresAt: d(63), Metadata: map[string]string{"issuer": "Google Trust Services"}},
			{Source: "www.google.com:443", Name: "www.google.com", Kind: "certificate", ExpiresAt: d(63), Metadata: map[string]string{"issuer": "Google Trust Services"}},
			{Source: "github.com:443", Name: "github.com", Kind: "certificate", ExpiresAt: d(65), Metadata: map[string]string{"issuer": "DigiCert"}},
			{Source: "aws.amazon.com:443", Name: "aws.amazon.com", Kind: "certificate", ExpiresAt: d(101), Metadata: map[string]string{"issuer": "DigiCert"}},
			{Source: "vmware.com:443", Name: "www.broadcom.com", Kind: "certificate", ExpiresAt: d(117), Metadata: map[string]string{"issuer": "DigiCert"}},
			{Source: "azure.microsoft.com:443", Name: "azure.microsoft.com", Kind: "certificate", ExpiresAt: d(129), Metadata: map[string]string{"issuer": "Microsoft Azure TLS Issuing CA"}},
			{Source: "linkedin.com:443", Name: "linkedin.com", Kind: "certificate", ExpiresAt: d(150), Metadata: map[string]string{"issuer": "DigiCert"}},
		}},
		{checkerName: "vault", records: []checker.ExpiryRecord{
			{Source: "vault://vault.demo.internal/pki", Name: "backend-prod · a1b2c3d4", Kind: "secret", ExpiresAt: d(9), Metadata: map[string]string{"mount": "pki"}},
			{Source: "vault://vault.demo.internal/token", Name: "ci-pipeline · e5f6a7b8", Kind: "token", ExpiresAt: d(21), Metadata: map[string]string{}},
			{Source: "vault://vault.demo.internal/ca", Name: "vault-ca", Kind: "ca_certificate", ExpiresAt: d(900), Metadata: map[string]string{}},
		}},
		{checkerName: "azure", records: []checker.ExpiryRecord{
			{Source: "azure://demo-kv.vault.azure.net", Name: "demo-db-connection-string", Kind: "secret", ExpiresAt: d(14), Metadata: map[string]string{"vault": "demo-kv"}},
			{Source: "azure://demo-kv.vault.azure.net", Name: "app-registration-client-secret", Kind: "secret", ExpiresAt: d(45), Metadata: map[string]string{"vault": "demo-kv"}},
			{Source: "azure://arm/subscriptions/demo/resourceGroups/rg-demo/providers/Microsoft.Compute/sshPublicKeys/demo", Name: "api-gateway.demo.internal · managed cert", Kind: "certificate", ExpiresAt: d(80), Metadata: map[string]string{}},
		}},
		{checkerName: "aws", records: []checker.ExpiryRecord{
			{Source: "aws://acm/123456789012/eu-west-1/demo-cert", Name: "api.demo.example.com", Kind: "certificate", ExpiresAt: d(70), Metadata: map[string]string{"region": "eu-west-1"}},
			{Source: "aws://iam/123456789012/user/ci-deploy/AKIADEMO0000000001@2026-08-01T00:00:00Z", Name: "ci-deploy · key 1", Kind: "access_key", ExpiresAt: d(5), Metadata: map[string]string{"rotation_days": "90"}},
			{Source: "aws://secretsmanager/123456789012/eu-west-1/demo/db-password", Name: "demo/db-password", Kind: "secret", ExpiresAt: d(30), Metadata: map[string]string{"region": "eu-west-1"}},
		}},
		{checkerName: "gcp", records: []checker.ExpiryRecord{
			{Source: "gcp://certificatemanager/demo-project/global/demo-cert", Name: "demo.example.com", Kind: "certificate", ExpiresAt: d(55), Metadata: map[string]string{"project": "demo-project"}},
			{Source: "gcp://iam/demo-project/ci@demo-project.iam.gserviceaccount.com/keys/0a0b0c0d", Name: "ci@demo-project.iam.gserviceaccount.com · 0a0b0c0d", Kind: "service_account_key", ExpiresAt: d(40), Metadata: map[string]string{"project": "demo-project"}},
		}},
		{checkerName: "vmware", records: []checker.ExpiryRecord{
			{Source: "vmware://vcenter.demo.internal/license/AB12C", Name: "vSphere 8 Enterprise Plus (…AB12C)", Kind: "license", ExpiresAt: d(200), Metadata: map[string]string{"edition": "esx.enterprisePlus.cpuPackage"}},
			{Source: "vmware://vcenter.demo.internal/machine-ssl", Name: "vcenter.demo.internal", Kind: "certificate", ExpiresAt: d(95), Metadata: map[string]string{}},
		}},
		{checkerName: "flexlm", records: []checker.ExpiryRecord{
			{Source: "flexlm:///opt/vendor-app/license.lic/CAD_SOLVER", Name: "CAD_SOLVER", Kind: "license", ExpiresAt: d(18), Metadata: map[string]string{"vendor_daemon": "vendord", "version": "2026.1", "count": "25"}},
			{Source: "flexlm:///opt/vendor-app/license.lic/SIMULATION", Name: "SIMULATION", Kind: "license", ExpiresAt: d(60), Metadata: map[string]string{"vendor_daemon": "vendord", "version": "2026.1", "count": "10"}},
		}},
	}

	for _, b := range batches {
		if err := s.SaveResult(ctx, demoAgentID, b.checkerName, b.records, now, true); err != nil {
			return fmt.Errorf("checker %s: %w", b.checkerName, err)
		}
		if err := s.RecordCheckerHealth(ctx, b.checkerName, demoAgentID, nil); err != nil {
			return fmt.Errorf("checker %s health: %w", b.checkerName, err)
		}
	}
	return nil
}
