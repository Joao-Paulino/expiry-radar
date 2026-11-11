package azure

import "testing"

const guid = "11111111-2222-3333-4444-555555555555"

func TestConfig_Validate(t *testing.T) {
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "")
	t.Setenv("AZURE_TENANT_ID", "")
	t.Setenv("AZURE_CLIENT_ID", "")
	base := func(auth string) Config {
		return Config{TenantID: guid, ClientID: guid, Auth: auth, CertificateFile: "/c.pem", TokenFile: "/t", KeyVaults: []string{"kv-prod-weu"}}
	}
	for _, a := range []string{"managed_identity", "certificate", "workload_identity"} {
		c := base(a)
		if err := c.Validate(); err != nil {
			t.Errorf("%s rejected: %v", a, err)
		}
	}
	mi := Config{Auth: "managed_identity", Subscriptions: []string{guid}}
	if err := mi.Validate(); err != nil {
		t.Errorf("managed identity without tenant/client rejected: %v", err)
	}
	cases := map[string]func(c *Config){
		"unknown auth":             func(c *Config) { c.Auth = "password" },
		"certificate without file": func(c *Config) { c.Auth = "certificate"; c.CertificateFile = "" },
		"certificate no tenant":    func(c *Config) { c.Auth = "certificate"; c.TenantID = "" },
		"wi without token file":    func(c *Config) { c.Auth = "workload_identity"; c.TokenFile = "" },
		"bad vault name":           func(c *Config) { c.KeyVaults = []string{"kv_bad!"} },
		"vault name too short":     func(c *Config) { c.KeyVaults = []string{"kv"} },
		"bad subscription":         func(c *Config) { c.Subscriptions = []string{"not-a-guid"} },
		"nothing to check":         func(c *Config) { c.KeyVaults = nil; c.Subscriptions = nil },
		"bad tenant":               func(c *Config) { c.TenantID = "x/../y" },
	}
	for name, mutate := range cases {
		c := base("certificate")
		mutate(&c)
		if c.Validate() == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestConfig_WorkloadIdentityEnvDefaults(t *testing.T) {
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "/var/run/secrets/azure/tokens/azure-identity-token")
	t.Setenv("AZURE_TENANT_ID", guid)
	t.Setenv("AZURE_CLIENT_ID", guid)
	c := Config{Auth: "workload_identity", KeyVaults: []string{"kv-prod-weu"}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.TokenFile == "" || c.TenantID != guid || c.ClientID != guid {
		t.Fatalf("env defaults not applied: %+v", c)
	}
}
