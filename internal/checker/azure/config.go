// Package azure checks Microsoft Azure for things that expire: Key Vault
// certificates, secrets and keys, and the client secrets and
// certificates of app registrations and enterprise apps. It uses the
// Entra ID, ARM, Key Vault and Microsoft Graph REST APIs directly (no
// Azure SDK) and only calls list endpoints, which return attributes,
// never values.
package azure

import (
	"errors"
	"fmt"
	"os"
	"regexp"
)

// Config is the agent's "azure" section. One tenant per agent.
type Config struct {
	TenantID        string   `json:"tenant_id"`
	ClientID        string   `json:"client_id"`
	Auth            string   `json:"auth"` // managed_identity | certificate | workload_identity
	CertificateFile string   `json:"certificate_file"`
	TokenFile       string   `json:"token_file"`
	KeyVaults       []string `json:"key_vaults"`
	Subscriptions   []string `json:"subscriptions"`
	// AppRegistrations / ServicePrincipals check client secrets and
	// certificates of every app (and SAML signing certificates of
	// enterprise apps) via Microsoft Graph; need Application.Read.All.
	AppRegistrations  bool `json:"app_registrations"`
	ServicePrincipals bool `json:"service_principals"`
}

var (
	vaultNameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{1,22}[A-Za-z0-9]$`)
	guidRe      = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)
	tenantRe    = regexp.MustCompile(`^[A-Za-z0-9.-]+$`) // GUID or domain
)

func envDefault(v *string, key string) {
	if *v == "" {
		*v = os.Getenv(key)
	}
}

// Validate applies the workload identity environment defaults (as
// injected by AKS) and reports a configuration that cannot work.
func (c *Config) Validate() error {
	if c.Auth == "workload_identity" {
		envDefault(&c.TokenFile, "AZURE_FEDERATED_TOKEN_FILE")
		envDefault(&c.TenantID, "AZURE_TENANT_ID")
		envDefault(&c.ClientID, "AZURE_CLIENT_ID")
	}
	switch c.Auth {
	case "managed_identity":
	case "certificate":
		if c.CertificateFile == "" {
			return errors.New("azure: auth certificate needs certificate_file")
		}
	case "workload_identity":
		if c.TokenFile == "" {
			return errors.New("azure: auth workload_identity needs token_file (or AZURE_FEDERATED_TOKEN_FILE)")
		}
	default:
		return errors.New("azure: auth must be managed_identity, certificate or workload_identity")
	}
	if c.Auth != "managed_identity" && (c.TenantID == "" || c.ClientID == "") {
		return fmt.Errorf("azure: auth %s needs tenant_id and client_id", c.Auth)
	}
	if c.TenantID != "" && !tenantRe.MatchString(c.TenantID) {
		return fmt.Errorf("azure: invalid tenant_id %q", c.TenantID)
	}
	if len(c.KeyVaults)+len(c.Subscriptions) == 0 && !c.AppRegistrations && !c.ServicePrincipals {
		return errors.New("azure: set at least one of key_vaults, subscriptions, app_registrations or service_principals")
	}
	for _, v := range c.KeyVaults {
		if !vaultNameRe.MatchString(v) {
			return fmt.Errorf("azure: invalid Key Vault name %q", v)
		}
	}
	for _, s := range c.Subscriptions {
		if !guidRe.MatchString(s) {
			return fmt.Errorf("azure: invalid subscription id %q", s)
		}
	}
	return nil
}
