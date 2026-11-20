package sso

import (
	"slices"
	"strings"

	"github.com/Joao-Paulino/expiry-radar/internal/collector/session"
)

// RoleFor assigns a role to a user who has already passed Authorize
// (the login gate). When a provider sets none of AdminGroups,
// AdminRoles, OperatorGroups or OperatorRoles, every authorized user
// keeps today's behavior: session.RoleAdmin. Once the provider
// configures at least one of those, a user is session.RoleAdmin if
// they match an admin group/role, session.RoleOperator if they match
// an operator group/role, and session.RoleViewer otherwise. Group
// comparison is case-insensitive, matching Authorize's own rule for
// Entra object IDs.
func RoleFor(p ProviderConfig, c Claims) string {
	if len(p.AdminGroups)+len(p.AdminRoles)+len(p.OperatorGroups)+len(p.OperatorRoles) == 0 {
		return session.RoleAdmin
	}
	if matchesAny(p.AdminRoles, c.Roles) || matchesAnyGroup(p.AdminGroups, c.Groups) {
		return session.RoleAdmin
	}
	if matchesAny(p.OperatorRoles, c.Roles) || matchesAnyGroup(p.OperatorGroups, c.Groups) {
		return session.RoleOperator
	}
	return session.RoleViewer
}

func matchesAny(allowed, got []string) bool {
	for _, g := range got {
		if slices.Contains(allowed, g) {
			return true
		}
	}
	return false
}

func matchesAnyGroup(allowed, got []string) bool {
	for _, g := range got {
		if slices.ContainsFunc(allowed, func(a string) bool { return strings.EqualFold(a, g) }) {
			return true
		}
	}
	return false
}
