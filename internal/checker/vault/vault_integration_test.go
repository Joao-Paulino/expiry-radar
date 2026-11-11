//go:build integration

package vault

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// TestIntegration_RealVaultPKI runs the checker against a real Vault
// prepared by scripts/ci/vault-smoke.sh, with the README's policy (which
// grants KV metadata only: reading a secret value would be denied).
func TestIntegration_RealVaultPKI(t *testing.T) {
	addr := os.Getenv("VAULT_TEST_ADDR")
	if addr == "" {
		t.Skip("VAULT_TEST_ADDR not set")
	}
	c := New(Config{Address: addr, CAFile: os.Getenv("VAULT_TEST_CA"), PKIMounts: []string{"pki"}, KVMounts: []string{"secret"}, CheckTokens: true, AppRoleMounts: []string{"approle"},
		Auth: Auth{AppRole: &AppRole{RoleID: os.Getenv("VAULT_TEST_ROLE_ID"), SecretIDFile: os.Getenv("VAULT_TEST_SECRET_ID_FILE")}}})
	recs, err := c.Check(context.Background())
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	var api, old, ca, kv, tok, sid int
	for _, r := range recs {
		t.Logf("%s %s %s expires %s", r.Kind, r.Name, r.Source, r.ExpiresAt.Format(time.RFC3339))
		switch {
		case r.Kind == "certificate" && r.Name == "api.example.com":
			api++
			if d := time.Until(r.ExpiresAt); d < 200*time.Hour {
				t.Errorf("api.example.com: reported the old certificate (%v left), want the renewed one", d)
			}
		case r.Name == "old.example.com":
			old++
		case r.Kind == "certificate" && r.Name == "Smoke Root CA":
			t.Errorf("CA certificate reported twice (as an issued certificate)")
		case r.Kind == "ca_certificate" && r.Name == "smoke-root":
			ca++
		case r.Kind == "token":
			tok++
			if !strings.Contains(r.Name, "ci-long") {
				t.Errorf("unexpected token %q (short-lived and root tokens must be skipped)", r.Name)
			}
		case r.Kind == "secret" && strings.HasPrefix(r.Name, "ci secret-id · "):
			sid++
		case r.Kind == "secret" && r.Metadata["role"] != "":
			// the agent's own secret ID (10m TTL): fine to report
		case r.Kind == "secret":
			kv++
			if r.Name != "apps/stripe" && r.Name != "apps/team/db" {
				t.Errorf("unexpected secret %q", r.Name)
			}
		}
	}
	if api != 1 || old != 0 || ca != 1 || kv != 2 || tok != 1 || sid != 1 {
		t.Fatalf("api=%d (want 1) revoked=%d (want 0) ca=%d (want 1) kv=%d (want 2) token=%d (want 1) ci secret-id=%d (want 1)",
			api, old, ca, kv, tok, sid)
	}
}
