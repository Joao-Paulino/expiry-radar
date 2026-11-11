package vault

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
)

func writeFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f")
	os.WriteFile(p, []byte(content), 0o600)
	return p
}

func appRoleConfig(t *testing.T, f *fakeVault, mounts ...string) Config {
	return Config{Address: f.srv.URL, Auth: Auth{AppRole: &AppRole{RoleID: "role-1", SecretIDFile: writeFile(t, "secret-1\n")}}, PKIMounts: mounts}
}

func newChecker(t *testing.T, f *fakeVault, cfg Config) *Checker {
	c := New(cfg)
	c.httpClient = f.srv.Client()
	return c
}

func TestConfig_Validate(t *testing.T) {
	ok := Config{Address: "https://vault:8200", Auth: Auth{TokenFile: "/x"}, PKIMounts: []string{"pki"}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	cases := map[string]func(c *Config){
		"http address":      func(c *Config) { c.Address = "http://vault:8200" },
		"no auth":           func(c *Config) { c.Auth = Auth{} },
		"two auths":         func(c *Config) { c.Auth.AppRole = &AppRole{RoleID: "r", SecretIDFile: "/s"} },
		"no mounts":         func(c *Config) { c.PKIMounts = nil },
		"bad mount":         func(c *Config) { c.PKIMounts = []string{"../sys"} },
		"approle no secret": func(c *Config) { c.Auth = Auth{AppRole: &AppRole{RoleID: "r"}} },
	}
	for name, mutate := range cases {
		c := ok
		mutate(&c)
		if c.Validate() == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestCheck_PKILatestPerNameAndIssuers(t *testing.T) {
	f := newFakeVault(t)
	now := time.Now()
	f.certs["pki"] = []fakeCert{
		{serial: "01", pem: makePEM(t, "api.example.com", now.Add(10*24*time.Hour), 1)}, // old, renewed
		{serial: "02", pem: makePEM(t, "api.example.com", now.Add(80*24*time.Hour), 2)}, // current
		{serial: "03", pem: makePEM(t, "revoked.example.com", now.Add(5*24*time.Hour), 3), revoked: true},
		{serial: "04", pem: makePEM(t, "gone.example.com", now.Add(-40*24*time.Hour), 4)}, // expired long ago
		{serial: "05", pem: makePEM(t, "late.example.com", now.Add(-2*24*time.Hour), 5)},  // just expired: report
	}
	f.issuers["pki"] = map[string]string{"iss-1": makePEM(t, "Example Root CA", now.Add(3650*24*time.Hour), 9)}
	f.issuerNm["pki"] = map[string]string{"iss-1": "root-2026"}

	recs, err := newChecker(t, f, appRoleConfig(t, f, "pki")).Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]checker.ExpiryRecord{}
	for _, r := range recs {
		if err := r.Validate(); err != nil {
			t.Fatalf("invalid record %+v: %v", r, err)
		}
		got[r.Kind+"|"+r.Name] = r
	}
	if len(got) != 3 {
		t.Fatalf("want 3 records (api, late, CA), got %d: %+v", len(got), recs)
	}
	api := got["certificate|api.example.com"]
	if api.Metadata["serial"] != "02" || api.Source != "vault://"+strings.TrimPrefix(f.srv.URL, "https://")+"/pki" {
		t.Fatalf("api: %+v", api)
	}
	if _, ok := got["certificate|late.example.com"]; !ok {
		t.Fatal("recently expired certificate not reported")
	}
	if ca, ok := got["ca_certificate|root-2026"]; !ok || ca.Metadata["common_name"] != "Example Root CA" {
		t.Fatalf("issuer: %+v", got)
	}
	if !f.revoked {
		t.Fatal("AppRole token not revoked after the run")
	}
	for _, p := range f.paths {
		if !strings.HasPrefix(p, "POST /v1/auth/") && !strings.HasPrefix(p, "GET /v1/pki/cert") && !strings.HasPrefix(p, "GET /v1/pki/issuer") {
			t.Errorf("unexpected request %q", p)
		}
	}
}

func TestCheck_TokenFileAndNamespace(t *testing.T) {
	f := newFakeVault(t)
	f.certs["pki"] = []fakeCert{{serial: "01", pem: makePEM(t, "a.example.com", time.Now().Add(24*time.Hour), 1)}}
	cfg := Config{Address: f.srv.URL, Namespace: "team-a", Auth: Auth{TokenFile: writeFile(t, "file-token\n")}, PKIMounts: []string{"pki"}}
	recs, err := newChecker(t, f, cfg).Check(context.Background())
	if err != nil || len(recs) != 1 {
		t.Fatalf("got %+v, %v", recs, err)
	}
	if f.revoked {
		t.Fatal("a configured token must not be revoked")
	}
	for i, ns := range f.namespace {
		if ns != "team-a" {
			t.Fatalf("request %s without namespace header", f.paths[i])
		}
	}
}

func TestCheck_FailingMountDoesNotHideOthers(t *testing.T) {
	f := newFakeVault(t)
	f.failMount = "broken"
	f.certs["pki"] = []fakeCert{{serial: "01", pem: makePEM(t, "a.example.com", time.Now().Add(24*time.Hour), 1)}}
	recs, err := newChecker(t, f, appRoleConfig(t, f, "broken", "pki")).Check(context.Background())
	if len(recs) != 1 || err == nil || !strings.Contains(err.Error(), "broken") {
		t.Fatalf("got %d records, err %v", len(recs), err)
	}
}

func TestCheck_LoginFailureIsAnError(t *testing.T) {
	f := newFakeVault(t)
	cfg := appRoleConfig(t, f, "pki")
	cfg.Auth.AppRole.SecretIDFile = writeFile(t, "wrong")
	if _, err := newChecker(t, f, cfg).Check(context.Background()); err == nil || !strings.Contains(err.Error(), "login") {
		t.Fatalf("got %v", err)
	}
}
