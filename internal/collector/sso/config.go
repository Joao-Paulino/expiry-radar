package sso

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// ProviderConfig is one OIDC provider, from collector.json.
type ProviderConfig struct {
	Name             string   `json:"name"`         // URL-safe id: /auth/<name>/...
	DisplayName      string   `json:"display_name"` // button label
	Issuer           string   `json:"issuer"`
	ClientID         string   `json:"client_id"`
	ClientSecretFile string   `json:"client_secret_file"`
	AllowedEmails    []string `json:"allowed_emails"` // verified emails only
	AllowedGroups    []string `json:"allowed_groups"` // "groups" claim (Entra object IDs)
	AllowedRoles     []string `json:"allowed_roles"`  // "roles" claim (Entra app roles)
}

var nameRe = regexp.MustCompile(`^[a-z0-9-]+$`)

// multiTenant are Entra issuers that accept accounts from any tenant.
var multiTenant = []string{"/common/", "/organizations/", "/consumers/"}

// ClientSecret reads the client secret file, trimmed.
func (p ProviderConfig) ClientSecret() (string, error) {
	b, err := os.ReadFile(p.ClientSecretFile)
	if err != nil {
		return "", fmt.Errorf("sso: provider %q: reading client_secret_file: %w", p.Name, err)
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", fmt.Errorf("sso: provider %q: client_secret_file is empty", p.Name)
	}
	return s, nil
}

// ValidateProviders checks every provider and the public URL used to
// build redirect URIs, so a misconfiguration fails at startup.
func ValidateProviders(ps []ProviderConfig, publicURL string) error {
	u, err := url.Parse(publicURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		return fmt.Errorf("sso: public_url must be an https URL with no path, e.g. https://collector.example.com:8443")
	}
	seen := map[string]bool{}
	for _, p := range ps {
		if !nameRe.MatchString(p.Name) {
			return fmt.Errorf("sso: provider name %q must match [a-z0-9-]+", p.Name)
		}
		if seen[p.Name] {
			return fmt.Errorf("sso: duplicate provider name %q", p.Name)
		}
		seen[p.Name] = true
		iu, err := url.Parse(p.Issuer)
		if err != nil || iu.Scheme != "https" || iu.Host == "" {
			return fmt.Errorf("sso: provider %q: issuer must be an https URL", p.Name)
		}
		for _, mt := range multiTenant {
			if strings.Contains(iu.Path+"/", mt) {
				return fmt.Errorf("sso: provider %q: multi-tenant issuer %q would accept accounts from any organization; use your tenant ID", p.Name, p.Issuer)
			}
		}
		if p.ClientID == "" {
			return fmt.Errorf("sso: provider %q: client_id is required", p.Name)
		}
		if len(p.AllowedEmails)+len(p.AllowedGroups)+len(p.AllowedRoles) == 0 {
			return fmt.Errorf("sso: provider %q: set at least one of allowed_emails, allowed_groups, allowed_roles", p.Name)
		}
		if _, err := p.ClientSecret(); err != nil {
			return err
		}
	}
	return nil
}

// RedirectURL is the callback URL to register with the provider.
func RedirectURL(publicURL, name string) string {
	return strings.TrimRight(publicURL, "/") + "/auth/" + name + "/callback"
}
