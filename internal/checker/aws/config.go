package aws

import (
	"errors"
	"fmt"
	"os"
	"regexp"
)

// AssumeRole is a read-only role in another account (multi-account).
type AssumeRole struct {
	RoleARN    string `json:"role_arn"`
	ExternalID string `json:"external_id"`
}

// Config is the agent's "aws" section.
type Config struct {
	Auth            string `json:"auth"` // instance_role | web_identity | roles_anywhere
	RoleARN         string `json:"role_arn"`
	TokenFile       string `json:"token_file"`
	CertificateFile string `json:"certificate_file"`
	TrustAnchorARN  string `json:"trust_anchor_arn"`
	ProfileARN      string `json:"profile_arn"`
	// Region for STS / Roles Anywhere; default the first of Regions.
	Region          string       `json:"region"`
	Regions         []string     `json:"regions"`
	AssumeRoles     []AssumeRole `json:"assume_roles"`
	SkipBaseAccount bool         `json:"skip_base_account"`
	// Services to check; default acm and iam_server_certificates.
	Services []string `json:"services"`
	// AccessKeyMaxAgeDays: an access key is due this many days after
	// its last rotation (default 90, CIS AWS Foundations).
	AccessKeyMaxAgeDays int `json:"access_key_max_age_days"`
}

var (
	// Standard AWS partition only: China, GovCloud and ISO use other
	// hosts and signing regions (not supported yet).
	regionRe  = regexp.MustCompile(`^(us|eu|ap|ca|sa|me|af|il|mx)-[a-z]+-\d$`)
	roleARNRe = regexp.MustCompile(`^arn:aws:iam::\d{12}:role/[\w+=,.@/-]{1,512}$`)
	raARNRe   = regexp.MustCompile(`^arn:aws:rolesanywhere:([a-z0-9-]+):\d{12}:(trust-anchor|profile)/[\w-]+$`)
	services  = map[string]bool{"acm": true, "iam_server_certificates": true, "access_keys": true}
	regional  = map[string]bool{"acm": true}
)

func (c *Config) services() []string {
	if len(c.Services) == 0 {
		return []string{"acm", "iam_server_certificates"}
	}
	return c.Services
}

// rolesAnywhereRegion is the trust anchor's region (as the official
// signing helper does).
func (c *Config) rolesAnywhereRegion() string {
	if m := raARNRe.FindStringSubmatch(c.TrustAnchorARN); m != nil {
		return m[1]
	}
	return c.stsRegion()
}

func (c *Config) stsRegion() string {
	if c.Region != "" {
		return c.Region
	}
	if len(c.Regions) > 0 {
		return c.Regions[0]
	}
	return "us-east-1"
}

// Validate applies the web identity environment defaults (as EKS IRSA
// injects them) and reports a configuration that cannot work.
func (c *Config) Validate() error {
	if c.Auth == "web_identity" {
		if c.TokenFile == "" {
			c.TokenFile = os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE")
		}
		if c.RoleARN == "" {
			c.RoleARN = os.Getenv("AWS_ROLE_ARN")
		}
	}
	switch c.Auth {
	case "instance_role":
	case "web_identity":
		if c.TokenFile == "" || !roleARNRe.MatchString(c.RoleARN) {
			return errors.New("aws: web_identity needs token_file and role_arn (or AWS_WEB_IDENTITY_TOKEN_FILE / AWS_ROLE_ARN)")
		}
	case "roles_anywhere":
		if c.CertificateFile == "" || !roleARNRe.MatchString(c.RoleARN) || !raARNRe.MatchString(c.TrustAnchorARN) || !raARNRe.MatchString(c.ProfileARN) {
			return errors.New("aws: roles_anywhere needs certificate_file, role_arn, trust_anchor_arn and profile_arn (standard aws partition)")
		}
		if c.rolesAnywhereRegion() != raARNRe.FindStringSubmatch(c.ProfileARN)[1] {
			return errors.New("aws: trust_anchor_arn and profile_arn must be in the same region")
		}
	default:
		return errors.New("aws: auth must be instance_role, web_identity or roles_anywhere (static access keys are not supported)")
	}
	needRegions := false
	for _, s := range c.services() {
		if !services[s] {
			return fmt.Errorf("aws: unknown service %q", s)
		}
		needRegions = needRegions || regional[s]
	}
	if needRegions && len(c.Regions) == 0 {
		return errors.New("aws: regions are required for acm")
	}
	for _, r := range append(append([]string{}, c.Regions...), c.Region) {
		if r != "" && !regionRe.MatchString(r) {
			return fmt.Errorf("aws: invalid region %q (standard aws partition only)", r)
		}
	}
	for _, a := range c.AssumeRoles {
		if !roleARNRe.MatchString(a.RoleARN) {
			return fmt.Errorf("aws: invalid assume_roles role_arn %q", a.RoleARN)
		}
	}
	if c.AccessKeyMaxAgeDays < 0 {
		return errors.New("aws: access_key_max_age_days must not be negative")
	}
	if c.SkipBaseAccount && len(c.AssumeRoles) == 0 {
		return errors.New("aws: skip_base_account needs assume_roles")
	}
	return nil
}
