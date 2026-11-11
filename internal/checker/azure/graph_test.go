package azure

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestCheck_AppRegistrationCredentials(t *testing.T) {
	f := newFake(t)
	soon := time.Now().Add(10 * 24 * time.Hour).UTC().Truncate(time.Second)
	ts := func(d time.Duration) string { return time.Now().Add(d).UTC().Format(time.RFC3339) }
	f.graph["applications"] = []map[string]any{
		{"id": "obj-1", "appId": "aaaaaaaa-1111-2222-3333-444444444444", "displayName": "Payments API",
			"passwordCredentials": []map[string]any{
				{"keyId": "k1", "displayName": "ci-secret", "endDateTime": soon.Format(time.RFC3339), "hint": "abc"},
				{"keyId": "k-old-12345678", "displayName": "", "endDateTime": ts(-60 * 24 * time.Hour)}, // long expired: noise
			},
			"keyCredentials": []map[string]any{{"keyId": "c1c1c1c1-0000", "displayName": "CN=payments", "endDateTime": ts(200 * 24 * time.Hour), "usage": "Verify"}}},
		{"id": "obj-2", "appId": "bbbbbbbb-1111-2222-3333-444444444444", "displayName": "Payments API", // same name, other app
			"passwordCredentials": []map[string]any{{"keyId": "k2abcdef99", "endDateTime": ts(-2 * 24 * time.Hour)}}}, // just expired: report
	}
	recs, err := newTestChecker(t, f, Config{AppRegistrations: true}).Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range recs {
		if err := r.Validate(); err != nil {
			t.Fatalf("invalid record %+v: %v", r, err)
		}
		got[r.Source+"|"+r.Kind+"|"+r.Name] = true
		for k, v := range r.Metadata {
			if k == "hint" || v == "abc" {
				t.Fatalf("secret hint stored: %+v", r.Metadata)
			}
		}
		if r.Name == "Payments API · ci-secret" && (!r.ExpiresAt.Equal(soon) || r.Metadata["app_id"] != "aaaaaaaa-1111-2222-3333-444444444444" || r.Metadata["key_id"] != "k1") {
			t.Fatalf("secret: %+v", r)
		}
	}
	src1 := "azure://graph.microsoft.com/applications/aaaaaaaa-1111-2222-3333-444444444444"
	src2 := "azure://graph.microsoft.com/applications/bbbbbbbb-1111-2222-3333-444444444444"
	for _, want := range []string{src1 + "|secret|Payments API · ci-secret", src1 + "|certificate|Payments API · CN=payments", src2 + "|secret|Payments API · k2abcdef"} {
		if !got[want] {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	if len(got) != 3 {
		t.Fatalf("want 3 records (long-expired skipped), got %v", got)
	}
	for _, p := range f.paths {
		if strings.HasPrefix(p, "GET /kv/") {
			t.Fatalf("Key Vault called without key_vaults: %q", p)
		}
	}
	for _, tok := range f.graphTokens {
		if tok != "Bearer mi-"+resGraph {
			t.Fatalf("Graph called with token %q", tok)
		}
	}
}

func TestCheck_ServicePrincipalSAMLCertificate(t *testing.T) {
	f := newFake(t)
	end := time.Now().Add(15 * 24 * time.Hour).UTC().Format(time.RFC3339)
	// A SAML signing certificate appears twice (Sign + Verify) with the same thumbprint.
	f.graph["servicePrincipals"] = []map[string]any{
		{"id": "sp-1", "appId": "cccccccc-1111-2222-3333-444444444444", "displayName": "Salesforce", "keyCredentials": []map[string]any{
			{"keyId": "s1", "displayName": "CN=Microsoft Azure Federated SSO Certificate", "endDateTime": end, "usage": "Sign", "customKeyIdentifier": "THUMB"},
			{"keyId": "s2", "displayName": "CN=Microsoft Azure Federated SSO Certificate", "endDateTime": end, "usage": "Verify", "customKeyIdentifier": "THUMB"},
		}},
		{"id": "sp-2", "appId": "dddddddd-1111-2222-3333-444444444444", "displayName": "No creds"},
	}
	recs, err := newTestChecker(t, f, Config{ServicePrincipals: true}).Check(context.Background())
	if err != nil || len(recs) != 1 {
		t.Fatalf("want one SAML certificate, got %+v, %v", recs, err)
	}
	if recs[0].Kind != "certificate" || recs[0].Source != "azure://graph.microsoft.com/servicePrincipals/cccccccc-1111-2222-3333-444444444444" {
		t.Fatalf("got %+v", recs[0])
	}
}

func TestCheck_GraphFailureDoesNotHideKeyVault(t *testing.T) {
	f := newFake(t)
	f.vaults["kv-prod"] = map[string][]map[string]any{"secrets": {item(f.srv.URL+"/kv/kv-prod/secrets/s", time.Now().Add(time.Hour).Unix(), true, false)}}
	f.graph["applications"] = []map[string]any{{"bad": func() {}}} // not encodable: fake answers with an error body
	recs, err := newTestChecker(t, f, Config{KeyVaults: []string{"kv-prod"}, AppRegistrations: true}).Check(context.Background())
	if len(recs) != 1 || err == nil || !strings.Contains(err.Error(), "applications") {
		t.Fatalf("got %d records, err %v", len(recs), err)
	}
}
