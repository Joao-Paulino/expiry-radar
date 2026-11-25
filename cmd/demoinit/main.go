// Command demoinit is the entrypoint of the demo image (collector,
// agent and demoinit/demoseed all in the one container — unlike a
// real deployment, which always runs collector and agent separately).
// It gives a freshly started "docker compose up" demo a working,
// logged-in-ready collector with real TLS data and no manual steps:
//
//  1. Generates a self-signed certificate on first run (skipped if one
//     already exists, so a restart doesn't rotate it).
//  2. Sets a fixed demo administrator password and a fresh TOTP secret
//     directly through the same admin.Store a real operator's
//     "set-admin-password"/"set-admin-totp" commands use, skipping the
//     interactive confirmation round-trip (there is no human typing a
//     live code into this container) — then writes the password, the
//     TOTP secret/URI and the one-time recovery codes to a credentials
//     file in the data directory, and prints them to stdout so they
//     show up in `docker compose logs`.
//  3. Seeds the database with realistic example data (see cmd/demoseed).
//  4. Starts a real Agent as a background process (deploy/demo/agent.json),
//     which pushes to the collector below over localhost exactly as a
//     real agent would push to a real collector, live-checking a
//     handful of real public domains' TLS certificates — this one
//     part of the demo's data is genuinely live, not synthetic. Known
//     demo-only wrinkle: if this background process ever exits,
//     nothing reaps it (there is no init system in this container) —
//     acceptable since the agent runs forever by design.
//  5. Replaces itself (exec) with the real collector binary, so the
//     container's PID 1 is the collector process and signals/shutdown
//     behave exactly as in a real deployment.
//
// All of this is demo-only tooling: it is never built into the
// collector/agent release images and never runs in a real deployment.
//
// Usage: demoinit <collector.json>
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/collector/admin"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/db"
)

// demoPassword is fixed for every demo instance: it is not a secret
// worth randomizing, since the recovery codes and TOTP secret (which
// actually gate a login) are generated fresh per instance and are
// never reused across demo containers.
const demoPassword = "ExpiryRadarDemo!2026" // #nosec G101 -- public demo-only password, published on purpose; the per-instance TOTP is what gates the login

const collectorBinary = "/usr/local/bin/collector"
const demoseedBinary = "/usr/local/bin/demoseed"
const agentBinary = "/usr/local/bin/agent"
const demoAgentConfig = "/etc/expiry-radar/agent.json"

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: demoinit <collector.json>")
		os.Exit(2)
	}
	cfgPath := os.Args[1]

	if err := run(cfgPath); err != nil {
		fmt.Fprintf(os.Stderr, "demoinit: %s\n", err)
		os.Exit(1)
	}

	// Replace this process with the real collector, so it becomes PID 1.
	env := os.Environ()
	err := syscall.Exec(collectorBinary, []string{collectorBinary, cfgPath}, env) // #nosec G204 -- fixed binary path, not user input
	fmt.Fprintf(os.Stderr, "demoinit: exec collector: %s\n", err)
	os.Exit(1)
}

type minimalConfig struct {
	DBPath      string `json:"db_path"`
	TLSCertFile string `json:"tls_cert_file"`
	TLSKeyFile  string `json:"tls_key_file"`
}

func run(cfgPath string) error {
	data, err := os.ReadFile(cfgPath) // #nosec G304 -- path is this container's own fixed config argument
	if err != nil {
		return fmt.Errorf("reading %s: %w", cfgPath, err)
	}
	var cfg minimalConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parsing %s: %w", cfgPath, err)
	}
	if cfg.DBPath == "" {
		return fmt.Errorf("%s: db_path is required", cfgPath)
	}

	if err := ensureCert(cfg); err != nil {
		return fmt.Errorf("certificate: %w", err)
	}

	sqlDB, err := db.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("opening %s: %w", cfg.DBPath, err)
	}
	defer sqlDB.Close()

	store := &admin.Store{DB: sqlDB}
	ctx := context.Background()
	acc, found, err := store.Get(ctx)
	if err != nil {
		return err
	}

	credsPath := filepath.Join(filepath.Dir(cfg.DBPath), "demo-credentials.txt")
	if found && acc.PasswordHash != "" && acc.TOTPSecret != "" {
		// Already configured from a previous run: show the same
		// credentials again rather than generating new ones (the old
		// recovery codes and TOTP secret are still the ones in the DB).
		b, readErr := os.ReadFile(credsPath) // #nosec G304 -- fixed path derived from this container's own config
		if readErr == nil {
			fmt.Print(string(b))
		} else {
			fmt.Println("demoinit: administrator account already configured; credentials file not found, see your README's fixed demo password")
		}
	} else {
		creds, err := configureAdmin(ctx, store)
		if err != nil {
			return fmt.Errorf("configuring administrator account: %w", err)
		}
		if err := os.WriteFile(credsPath, []byte(creds), 0o600); err != nil {
			return fmt.Errorf("writing %s: %w", credsPath, err)
		}
		fmt.Print(creds)
	}

	if err := runDemoseed(cfgPath); err != nil {
		return fmt.Errorf("seeding example data: %w", err)
	}

	if err := startAgent(); err != nil {
		return fmt.Errorf("starting demo agent: %w", err)
	}
	return nil
}

// ensureCert generates a self-signed certificate for the demo on first
// run. gen-cert refuses to overwrite an existing cert/key, so this is
// safe to call again on every restart.
func ensureCert(cfg minimalConfig) error {
	if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
		return nil
	}
	if _, err := os.Stat(cfg.TLSCertFile); err == nil {
		return nil // already generated in an earlier run
	}
	dir := filepath.Dir(cfg.TLSCertFile)
	cmd := exec.Command(collectorBinary, "gen-cert", dir, "--host", "localhost") // #nosec G204 -- fixed binary and flags, dir comes from this container's own config
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// startAgent launches the real Agent (deploy/demo/agent.json, baked into
// the image alongside collector.json) as a background subprocess that
// keeps running after this function returns — it is never waited on.
// It pushes to the collector below over localhost, exactly as a real
// agent would push to a real collector, and is what makes this demo's
// TLS data genuinely live rather than synthetic.
//
// Known demo-only wrinkle: once this process execs into the collector
// binary (see main), nothing in this container can wait() on the
// agent if it ever exits — there is no init system here to reap it.
// Acceptable since the agent is designed to run forever.
func startAgent() error {
	cmd := exec.Command(agentBinary, demoAgentConfig) // #nosec G204 -- fixed binary and config path, not user input
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Start()
}

func runDemoseed(cfgPath string) error {
	cmd := exec.Command(demoseedBinary, cfgPath) // #nosec G204 -- fixed binary path, cfgPath is this container's own fixed argument
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// configureAdmin sets the fixed demo password and a fresh TOTP secret
// directly in the store, bypassing the interactive CLI confirmation
// (there is no operator here to type a live code back), and returns
// the credentials text to show the user.
func configureAdmin(ctx context.Context, store *admin.Store) (string, error) {
	hash, err := admin.HashPassword(demoPassword)
	if err != nil {
		return "", err
	}
	if err := store.SetPassword(ctx, hash); err != nil {
		return "", err
	}

	secret, err := admin.NewTOTPSecret()
	if err != nil {
		return "", err
	}
	plainCodes, hashedCodes, err := admin.NewRecoveryCodes()
	if err != nil {
		return "", err
	}
	if err := store.SetTOTP(ctx, secret, hashedCodes); err != nil {
		return "", err
	}

	uri := admin.TOTPURI(secret)
	code, err := admin.TOTPCode(secret, time.Now().Unix()/30)
	if err != nil {
		return "", err
	}

	var b []byte
	b = appendLine(b, "==================================================================")
	b = appendLine(b, "Expiry Radar demo — administrator login")
	b = appendLine(b, "==================================================================")
	b = appendLine(b, "")
	b = appendLine(b, fmt.Sprintf("  Password: %s", demoPassword))
	b = appendLine(b, "")
	b = appendLine(b, "  Second factor — pick ONE of the following:")
	b = appendLine(b, "")
	b = appendLine(b, "  a) Scan/add this into an authenticator app (Google Authenticator, etc.):")
	b = appendLine(b, fmt.Sprintf("     Key: %s", secret))
	b = appendLine(b, fmt.Sprintf("     URI: %s", uri))
	b = appendLine(b, fmt.Sprintf("     (right now its code is %s, but it changes every 30s — use the app)", code))
	b = appendLine(b, "")
	b = appendLine(b, "  b) Or use one of these one-time recovery codes instead of a TOTP code:")
	for _, c := range plainCodes {
		b = appendLine(b, fmt.Sprintf("     %s", c))
	}
	b = appendLine(b, "")
	b = appendLine(b, "This file (demo-credentials.txt, next to the database) is the only copy —")
	b = appendLine(b, "the recovery codes are hashed in the database and cannot be shown again.")
	b = appendLine(b, "==================================================================")
	b = appendLine(b, "")
	return string(b), nil
}

func appendLine(b []byte, s string) []byte {
	return append(append(b, []byte(s)...), '\n')
}
