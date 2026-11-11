package sso

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validProvider(t *testing.T) ProviderConfig {
	t.Helper()
	secret := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(secret, []byte("s3cret\n"), 0o600)
	return ProviderConfig{
		Name: "microsoft", DisplayName: "Microsoft",
		Issuer:   "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0",
		ClientID: "client", ClientSecretFile: secret, AllowedGroups: []string{"g1"},
	}
}

func TestValidateProviders(t *testing.T) {
	const pub = "https://collector.example.com:8443"
	if err := ValidateProviders([]ProviderConfig{validProvider(t)}, pub); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	cases := map[string]func(p *ProviderConfig){
		"bad name":            func(p *ProviderConfig) { p.Name = "Micro Soft" },
		"http issuer":         func(p *ProviderConfig) { p.Issuer = "http://idp.example.com" },
		"entra common":        func(p *ProviderConfig) { p.Issuer = "https://login.microsoftonline.com/common/v2.0" },
		"entra organizations": func(p *ProviderConfig) { p.Issuer = "https://login.microsoftonline.com/organizations/v2.0" },
		"entra consumers":     func(p *ProviderConfig) { p.Issuer = "https://login.microsoftonline.com/consumers/v2.0" },
		"entra Common casing": func(p *ProviderConfig) { p.Issuer = "https://login.microsoftonline.com/Common/v2.0" },
		"entra MSA tenant": func(p *ProviderConfig) {
			p.Issuer = "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0"
		},
		"no client id":   func(p *ProviderConfig) { p.ClientID = "" },
		"no allow rule":  func(p *ProviderConfig) { p.AllowedGroups = nil },
		"missing secret": func(p *ProviderConfig) { p.ClientSecretFile = "/nonexistent" },
	}
	for name, mutate := range cases {
		p := validProvider(t)
		mutate(&p)
		if err := ValidateProviders([]ProviderConfig{p}, pub); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	empty := validProvider(t)
	os.WriteFile(empty.ClientSecretFile, []byte("  \n"), 0o600)
	if ValidateProviders([]ProviderConfig{empty}, pub) == nil {
		t.Error("empty secret file accepted")
	}
	a, b := validProvider(t), validProvider(t)
	if ValidateProviders([]ProviderConfig{a, b}, pub) == nil {
		t.Error("duplicate provider names accepted")
	}
	for _, bad := range []string{"", "http://collector:8443", "https://collector:8443/path?x"} {
		if err := ValidateProviders([]ProviderConfig{validProvider(t)}, bad); err == nil || !strings.Contains(err.Error(), "public_url") {
			t.Errorf("public_url %q: got %v", bad, err)
		}
	}
}

func TestProviderConfig_ClientSecretTrimmed(t *testing.T) {
	p := validProvider(t)
	s, err := p.ClientSecret()
	if err != nil || s != "s3cret" {
		t.Fatalf("got %q, %v", s, err)
	}
}
