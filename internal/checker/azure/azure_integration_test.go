//go:build integration

package azure

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestIntegration_AzureKeyVault runs the checker against a real Key
// Vault as a workload identity (GitHub Actions OIDC in CI). The vault
// holds er-test-cert, er-test-secret and er-test-key with expiry dates
// and an identity with only Key Vault Reader (see README).
func TestIntegration_AzureKeyVault(t *testing.T) {
	vault := os.Getenv("AZURE_TEST_VAULT")
	if vault == "" {
		t.Skip("AZURE_TEST_VAULT not set")
	}
	cfg := Config{Auth: "workload_identity", TenantID: os.Getenv("AZURE_TEST_TENANT_ID"), ClientID: os.Getenv("AZURE_TEST_CLIENT_ID"),
		TokenFile: os.Getenv("AZURE_TEST_TOKEN_FILE"), KeyVaults: []string{vault}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	recs, err := New(cfg).Check(context.Background())
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	seen := map[string]bool{}
	for _, r := range recs {
		t.Logf("%s %s %s expires %s", r.Kind, r.Name, r.Source, r.ExpiresAt.Format(time.RFC3339))
		seen[r.Kind+"|"+r.Name] = true
	}
	for _, want := range []string{"certificate|er-test-cert", "secret|er-test-secret", "key|er-test-key"} {
		if !seen[want] {
			t.Errorf("missing %s", want)
		}
	}
	if seen["secret|er-test-cert"] || seen["key|er-test-cert"] {
		t.Error("managed secret/key behind the certificate reported")
	}
}
