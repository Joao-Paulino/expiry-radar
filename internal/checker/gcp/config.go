// Package gcp checks Google Cloud for things that expire: Certificate
// Manager and Compute SSL certificates, service account keys and Secret
// Manager. Go standard library only (no Google SDK), read-only, never a
// secret value. Projects come from an organization / folder scope via
// Cloud Asset Inventory (discovery only: dates always come from the
// service APIs, as Asset Inventory can lag by days) or from a list.
package gcp

import (
	"errors"
	"fmt"
	"regexp"
)

// Config is the agent's "gcp" section.
type Config struct {
	Auth string `json:"auth"` // metadata | external_account
	// CredentialFile: Google "external_account" configuration (workload
	// identity federation, file-sourced token). Service account key
	// files are not supported, on purpose.
	CredentialFile string   `json:"credential_file"`
	Organization   string   `json:"organization"` // organization ID: discover projects
	Folders        []string `json:"folders"`      // folder IDs: discover projects
	Projects       []string `json:"projects"`     // explicit project IDs or numbers
	Services       []string `json:"services"`     // default certificate_manager, compute_ssl
	KeyMaxAgeDays  int      `json:"key_max_age_days"`
}

var (
	idRe      = regexp.MustCompile(`^\d{1,20}$`)
	projectRe = regexp.MustCompile(`^([a-z][a-z0-9-]{4,28}[a-z0-9]|\d{1,20})$`)
	services  = map[string]bool{"certificate_manager": true, "compute_ssl": true, "service_account_keys": true, "secret_manager": true}
)

func (c *Config) services() []string {
	if len(c.Services) == 0 {
		return []string{"certificate_manager", "compute_ssl"}
	}
	return c.Services
}

// scopes are the Asset Inventory scopes to discover projects in.
func (c *Config) scopes() []string {
	var s []string
	if c.Organization != "" {
		s = append(s, "organizations/"+c.Organization)
	}
	for _, f := range c.Folders {
		s = append(s, "folders/"+f)
	}
	return s
}

func (c *Config) Validate() error {
	switch c.Auth {
	case "metadata":
	case "external_account":
		if c.CredentialFile == "" {
			return errors.New("gcp: external_account needs credential_file")
		}
	default:
		return errors.New("gcp: auth must be metadata or external_account (service account key files are not supported)")
	}
	if c.Organization == "" && len(c.Folders)+len(c.Projects) == 0 {
		return errors.New("gcp: set organization, folders or projects")
	}
	if c.Organization != "" && !idRe.MatchString(c.Organization) {
		return fmt.Errorf("gcp: invalid organization %q (numeric ID)", c.Organization)
	}
	for _, f := range c.Folders {
		if !idRe.MatchString(f) {
			return fmt.Errorf("gcp: invalid folder %q (numeric ID)", f)
		}
	}
	for _, p := range c.Projects {
		if !projectRe.MatchString(p) {
			return fmt.Errorf("gcp: invalid project %q", p)
		}
	}
	for _, s := range c.services() {
		if !services[s] {
			return fmt.Errorf("gcp: unknown service %q", s)
		}
	}
	if c.KeyMaxAgeDays < 0 || c.KeyMaxAgeDays > 3650 {
		return errors.New("gcp: key_max_age_days must be between 0 (default 90) and 3650")
	}
	return nil
}
