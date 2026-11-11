package azure

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
)

func newTestChecker(t *testing.T, f *fakeAzure, cfg Config) *Checker {
	t.Helper()
	if cfg.Auth == "" {
		cfg.Auth = "managed_identity"
	}
	c := New(cfg)
	c.http = f.srv.Client()
	c.ep = testEndpoints(f)
	c.getenv = noEnv
	return c
}

func byName(t *testing.T, recs []checker.ExpiryRecord) map[string]checker.ExpiryRecord {
	t.Helper()
	m := map[string]checker.ExpiryRecord{}
	for _, r := range recs {
		if err := r.Validate(); err != nil {
			t.Fatalf("invalid record %+v: %v", r, err)
		}
		m[r.Kind+"|"+r.Name] = r
	}
	return m
}

func TestCheck_KeyVaultItems(t *testing.T) {
	f := newFake(t)
	exp := time.Date(2027, 3, 31, 0, 0, 0, 0, time.UTC).Unix()
	base := f.srv.URL + "/kv/kv-prod/"
	key := func(name string, exp int64, managed bool) map[string]any {
		m := item("", exp, true, managed)
		delete(m, "id")
		m["kid"] = base + "keys/" + name
		return m
	}
	f.vaults["kv-prod"] = map[string][]map[string]any{
		"certificates": {item(base+"certificates/api-cert", exp, true, false), item(base+"certificates/no-exp", 0, true, false)},
		"secrets": {
			item(base+"secrets/stripe-key", exp, true, false),
			item(base+"secrets/api-cert", exp, true, true), // backs the certificate
			item(base+"secrets/disabled", exp, false, false),
		},
		"keys": {key("signing", exp, false), key("api-cert", exp, true)},
	}
	recs, err := newTestChecker(t, f, Config{KeyVaults: []string{"kv-prod"}}).Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := byName(t, recs)
	if len(got) != 3 {
		t.Fatalf("want api-cert, stripe-key, signing; got %+v", recs)
	}
	c := got["certificate|api-cert"]
	if c.Source != "azure://kv-prod.vault.azure.net" || c.ExpiresAt.Unix() != exp || c.Metadata["vault"] != "kv-prod" {
		t.Fatalf("certificate: %+v", c)
	}
	if _, ok := got["secret|stripe-key"]; !ok {
		t.Fatal("secret missing")
	}
	if _, ok := got["key|signing"]; !ok {
		t.Fatal("key missing")
	}
	for _, p := range f.paths {
		if strings.HasPrefix(p, "GET /kv/") && strings.Count(p, "/") != 3 {
			t.Fatalf("non-list endpoint requested: %q", p)
		}
	}
}

func TestCheck_Discovery(t *testing.T) {
	f := newFake(t)
	exp := time.Now().Add(20 * 24 * time.Hour).Unix()
	for _, v := range []string{"kv-weu", "kv-neu"} {
		f.vaults[v] = map[string][]map[string]any{"secrets": {item(f.srv.URL+"/kv/"+v+"/secrets/s", exp, true, false)}}
	}
	f.subs[guid] = []map[string]any{
		{"id": "/subscriptions/" + guid + "/resourceGroups/rg-weu/providers/Microsoft.KeyVault/vaults/kv-weu", "name": "kv-weu", "location": "westeurope"},
		{"id": "/subscriptions/" + guid + "/resourceGroups/rg-neu/providers/Microsoft.KeyVault/vaults/kv-neu", "name": "kv-neu", "location": "northeurope"},
	}
	recs, err := newTestChecker(t, f, Config{KeyVaults: []string{"KV-WEU"}, Subscriptions: []string{guid}}).Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("want one secret per vault (KV-WEU listed and discovered is checked once), got %+v", recs)
	}
	for _, r := range recs {
		if r.Metadata["subscription"] != guid || r.Metadata["location"] == "" || !strings.HasPrefix(r.Metadata["resource_group"], "rg-") {
			t.Fatalf("discovery metadata missing: %+v", r)
		}
	}
}

func TestCheck_FailingVaultDoesNotHideOthers(t *testing.T) {
	f := newFake(t)
	f.failVault = "kv-closed"
	f.vaults["kv-open"] = map[string][]map[string]any{"secrets": {item(f.srv.URL+"/kv/kv-open/secrets/s", time.Now().Add(time.Hour).Unix(), true, false)}}
	recs, err := newTestChecker(t, f, Config{KeyVaults: []string{"kv-closed", "kv-open"}}).Check(context.Background())
	if len(recs) != 1 || err == nil || !strings.Contains(err.Error(), "kv-closed") || !strings.Contains(err.Error(), "ForbiddenByFirewall") {
		t.Fatalf("got %d records, err %v", len(recs), err)
	}
}

func TestCheck_AuthFailureIsError(t *testing.T) {
	f := newFake(t)
	f.failToken = true
	cfg := Config{Auth: "certificate", TenantID: guid, ClientID: "app", CertificateFile: f.writeCertPEM(t), KeyVaults: []string{"kv-prod"}}
	if _, err := newTestChecker(t, f, cfg).Check(context.Background()); err == nil || !strings.Contains(err.Error(), "AADSTS") {
		t.Fatalf("got %v", err)
	}
}

func TestCheck_NextLinkOtherHostRefused(t *testing.T) {
	f := newFake(t)
	f.evilNextLink = true
	exp := time.Now().Add(time.Hour).Unix()
	f.vaults["kv-prod"] = map[string][]map[string]any{"secrets": {
		item(f.srv.URL+"/kv/kv-prod/secrets/a", exp, true, false), item(f.srv.URL+"/kv/kv-prod/secrets/b", exp, true, false)}}
	_, err := newTestChecker(t, f, Config{KeyVaults: []string{"kv-prod"}}).Check(context.Background())
	if err == nil || !strings.Contains(err.Error(), "nextLink") {
		t.Fatalf("nextLink to another host not refused: %v", err)
	}
}

func TestCheck_Pagination(t *testing.T) {
	f := newFake(t)
	exp := time.Now().Add(time.Hour).Unix()
	f.vaults["kv-prod"] = map[string][]map[string]any{"secrets": {
		item(f.srv.URL+"/kv/kv-prod/secrets/a", exp, true, false), item(f.srv.URL+"/kv/kv-prod/secrets/b", exp, true, false)}}
	recs, err := newTestChecker(t, f, Config{KeyVaults: []string{"kv-prod"}}).Check(context.Background())
	if err != nil || len(recs) != 2 {
		t.Fatalf("got %+v, %v", recs, err)
	}
}
