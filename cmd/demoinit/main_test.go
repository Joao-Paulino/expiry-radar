package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadOrCreateTokensIsRandomAndStable(t *testing.T) {
	dir := t.TempDir()
	a, err := loadOrCreateTokens(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Agent) < 32 || len(a.Admin) < 32 || a.Agent == a.Admin {
		t.Fatalf("weak or equal tokens: %+v", a)
	}
	for _, v := range []string{a.Agent, a.Admin} {
		if isPlaceholder(v) {
			t.Fatalf("a generated token must not look like a placeholder: %q", v)
		}
	}
	b, err := loadOrCreateTokens(dir)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("a restart must keep the same tokens, or the agent and the collector disagree")
	}
	if other, _ := loadOrCreateTokens(t.TempDir()); other == a {
		t.Fatal("two instances must not share tokens")
	}
	info, err := os.Stat(filepath.Join(dir, "demo-tokens.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Windows has no Unix permission bits; the demo itself only runs in a Linux container.
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("tokens file must be private, mode %v", info.Mode())
	}
}

func TestApplyTokensReplacesEveryPublishedToken(t *testing.T) {
	tok := demoTokens{Agent: "agent-token-agent-token-agent-token-0000", Admin: "admin-token-admin-token-admin-token-0000"}
	for _, in := range []string{
		`{"auth_tokens":["generate-on-first-start"],"admin_tokens":["generate-on-first-start"]}`,
		`{"auth_tokens":["ExpiryRadarDemoTLSAgentToken2026NotASecretJustADemo"],"admin_tokens":["demo-unused-admin-token-not-needed-for-the-dashboard-login"]}`,
	} {
		out, err := applyTokens([]byte(in), tok)
		if err != nil {
			t.Fatal(err)
		}
		var cfg map[string][]string
		if err := json.Unmarshal(out, &cfg); err != nil {
			t.Fatal(err)
		}
		if len(cfg["auth_tokens"]) != 1 || cfg["auth_tokens"][0] != tok.Agent {
			t.Fatalf("auth_tokens = %v", cfg["auth_tokens"])
		}
		if len(cfg["admin_tokens"]) != 1 || cfg["admin_tokens"][0] != tok.Admin {
			t.Fatalf("admin_tokens = %v", cfg["admin_tokens"])
		}
	}
}

func TestApplyTokensKeepsOperatorTokensAndOtherFields(t *testing.T) {
	tok := demoTokens{Agent: "agent-token-agent-token-agent-token-0000", Admin: "admin-token-admin-token-admin-token-0000"}
	in := `{"db_path":"/data/radar.db","oidc_providers":[{"name":"keycloak"}],` +
		`"auth_tokens":["operator-agent-token-operator-agent-token"],"admin_tokens":["operator-admin-token-operator-admin-token"]}`
	out, err := applyTokens([]byte(in), tok)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["db_path"] != "/data/radar.db" || cfg["oidc_providers"] == nil {
		t.Fatalf("other fields must survive: %v", cfg)
	}
	adm := cfg["admin_tokens"].([]any)
	if len(adm) != 1 || adm[0] != "operator-admin-token-operator-admin-token" {
		t.Fatalf("a token chosen by the operator must be kept: %v", adm)
	}
	auth := cfg["auth_tokens"].([]any)
	if len(auth) != 2 || auth[1] != tok.Agent {
		t.Fatalf("the in-container agent token must be accepted too: %v", auth)
	}
}

func TestAgentConfigWithToken(t *testing.T) {
	out, err := agentConfigWithToken([]byte(`{"token":"generate-on-first-start","agent_id":"x"}`), "secret-secret-secret-secret-secret-12")
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]string
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["token"] != "secret-secret-secret-secret-secret-12" || cfg["agent_id"] != "x" {
		t.Fatalf("cfg = %v", cfg)
	}
}
