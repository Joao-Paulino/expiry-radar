package sso

import (
	"encoding/json"
	"slices"
	"strings"
)

// flexBool accepts true/false as a JSON boolean or string (some
// providers send "true").
type flexBool bool

func (b *flexBool) UnmarshalJSON(data []byte) error {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	switch x := v.(type) {
	case bool:
		*b = flexBool(x)
	case string:
		*b = flexBool(strings.EqualFold(x, "true"))
	}
	return nil
}

// Claims are the ID-token claims Expiry Radar uses.
type Claims struct {
	Subject       string         `json:"sub"`
	Email         string         `json:"email"`
	EmailVerified flexBool       `json:"email_verified"`
	Groups        []string       `json:"groups"`
	Roles         []string       `json:"roles"`
	ClaimNames    map[string]any `json:"_claim_names"` // Entra groups overage marker
}

// Authorize reports whether the claims satisfy any of the provider's
// allow rules, and why not. Emails count only when verified; groups and
// roles come from Entra. Microsoft advises against authorizing on email
// or preferred_username, so prefer groups/roles there.
func Authorize(p ProviderConfig, c Claims) (bool, string) {
	for _, r := range c.Roles {
		if slices.Contains(p.AllowedRoles, r) {
			return true, ""
		}
	}
	for _, g := range c.Groups { // object IDs: compare without case
		if slices.ContainsFunc(p.AllowedGroups, func(a string) bool { return strings.EqualFold(a, g) }) {
			return true, ""
		}
	}
	// Only an explicit email_verified=true counts. Entra ID tokens do not
	// carry it (and Microsoft says the email claim is mutable), so an
	// Entra email never matches: never treat a missing claim as true.
	if c.Email != "" && len(p.AllowedEmails) > 0 {
		listed := slices.ContainsFunc(p.AllowedEmails, func(e string) bool { return strings.EqualFold(e, c.Email) })
		if listed && bool(c.EmailVerified) {
			return true, ""
		}
		if listed {
			return false, "email is listed but not verified by the provider"
		}
	}
	if _, overage := c.ClaimNames["groups"]; overage && len(p.AllowedGroups) > 0 {
		return false, "groups overage: the token omits groups (more than 200); use app roles or assign groups to the application"
	}
	return false, "not allowed by allowed_emails, allowed_groups or allowed_roles"
}
