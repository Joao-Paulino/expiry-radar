//go:build integration

package vault

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestIntegration_RealVaultPKI runs the checker against a real Vault
// prepared by scripts/ci/vault-smoke.sh, with the README's policy.
func TestIntegration_RealVaultPKI(t *testing.T) {
	addr := os.Getenv("VAULT_TEST_ADDR")
	if addr == "" {
		t.Skip("VAULT_TEST_ADDR not set")
	}
	c := New(Config{Address: addr, CAFile: os.Getenv("VAULT_TEST_CA"), PKIMounts: []string{"pki"},
		Auth: Auth{AppRole: &AppRole{RoleID: os.Getenv("VAULT_TEST_ROLE_ID"), SecretIDFile: os.Getenv("VAULT_TEST_SECRET_ID_FILE")}}})
	recs, err := c.Check(context.Background())
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	var api, old, ca int
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
		}
	}
	if api != 1 || old != 0 || ca != 1 {
		t.Fatalf("api=%d (want 1) revoked=%d (want 0) ca=%d (want 1)", api, old, ca)
	}
}
