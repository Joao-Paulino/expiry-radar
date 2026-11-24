package sso

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/Joao-Paulino/expiry-radar/internal/collector/session"
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

	// RBAC (see RoleFor): a user who passes Authorize above (the
	// login gate) is then assigned a role by matching these against
	// the "groups"/"roles" claims. When none of the four are set for
	// this provider, every authorized user keeps today's behavior —
	// full admin access — so adding RBAC to one provider never
	// silently restricts another. AdminGroups/AdminRoles are checked
	// before OperatorGroups/OperatorRoles; a user matching neither
	// falls through to DefaultRole, or to a read-only viewer role if
	// DefaultRole is unset.
	AdminGroups    []string `json:"admin_groups"`
	AdminRoles     []string `json:"admin_roles"`
	OperatorGroups []string `json:"operator_groups"`
	OperatorRoles  []string `json:"operator_roles"`

	// DefaultRole is the role granted to an authorized user who
	// matches none of the four keys above, once RBAC is active for
	// this provider (i.e. at least one of the four is set). It exists
	// for providers whose tokens never carry group/role claims at all
	// (Google, for example): such a provider can never match
	// AdminGroups/AdminRoles/OperatorGroups/OperatorRoles, so without
	// DefaultRole every authorized user there is stuck at viewer.
	// Must be "admin", "operator" or "viewer" when set; empty keeps
	// the viewer fallback. Setting DefaultRole never overrides an
	// actual admin/operator match.
	DefaultRole string `json:"default_role"`
}

var nameRe = regexp.MustCompile(`^[a-z0-9-]+$`)

// multiTenant are Entra issuer path segments that accept accounts from
// any tenant or any personal Microsoft account (the last one is the
// documented tenant ID of personal accounts).
var multiTenant = []string{"/common/", "/organizations/", "/consumers/", "/9188040d-6c67-4c5b-b112-36a304b66dad/"}

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
			if strings.Contains(strings.ToLower(iu.Path)+"/", mt) {
				return fmt.Errorf("sso: provider %q: multi-tenant issuer %q would accept accounts from any organization; use your tenant ID", p.Name, p.Issuer)
			}
		}
		if p.ClientID == "" {
			return fmt.Errorf("sso: provider %q: client_id is required", p.Name)
		}
		if len(p.AllowedEmails)+len(p.AllowedGroups)+len(p.AllowedRoles) == 0 {
			return fmt.Errorf("sso: provider %q: set at least one of allowed_emails, allowed_groups, allowed_roles", p.Name)
		}
		switch p.DefaultRole {
		case "", session.RoleAdmin, session.RoleOperator, session.RoleViewer:
		default:
			return fmt.Errorf("sso: provider %q: default_role must be %q, %q or %q", p.Name, session.RoleAdmin, session.RoleOperator, session.RoleViewer)
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
