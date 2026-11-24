package sso

import (
	"testing"

	"github.com/Joao-Paulino/expiry-radar/internal/collector/session"
)

// TestRoleFor_NoKeysConfiguredKeepsFullAccess proves a provider with
// none of the four RBAC keys set assigns every authorized user the
// admin role, so enabling RBAC on one provider never silently
// restricts a provider that hasn't opted in.
func TestRoleFor_NoKeysConfiguredKeepsFullAccess(t *testing.T) {
	p := ProviderConfig{AllowedGroups: []string{"g1"}}
	c := Claims{Groups: []string{"g1"}}
	if got := RoleFor(p, c); got != session.RoleAdmin {
		t.Fatalf("got %q, want %q", got, session.RoleAdmin)
	}
}

func TestRoleFor_MatchesAdminGroup(t *testing.T) {
	p := ProviderConfig{AdminGroups: []string{"admins-oid"}, OperatorGroups: []string{"ops-oid"}}
	c := Claims{Groups: []string{"admins-oid"}}
	if got := RoleFor(p, c); got != session.RoleAdmin {
		t.Fatalf("got %q, want %q", got, session.RoleAdmin)
	}
}

func TestRoleFor_MatchesAdminRole(t *testing.T) {
	p := ProviderConfig{AdminRoles: []string{"ExpiryRadar.Admin"}}
	c := Claims{Roles: []string{"ExpiryRadar.Admin"}}
	if got := RoleFor(p, c); got != session.RoleAdmin {
		t.Fatalf("got %q, want %q", got, session.RoleAdmin)
	}
}

func TestRoleFor_MatchesOperatorGroup(t *testing.T) {
	p := ProviderConfig{AdminGroups: []string{"admins-oid"}, OperatorGroups: []string{"ops-oid"}}
	c := Claims{Groups: []string{"ops-oid"}}
	if got := RoleFor(p, c); got != session.RoleOperator {
		t.Fatalf("got %q, want %q", got, session.RoleOperator)
	}
}

func TestRoleFor_MatchesOperatorRole(t *testing.T) {
	p := ProviderConfig{OperatorRoles: []string{"ExpiryRadar.Operator"}}
	c := Claims{Roles: []string{"ExpiryRadar.Operator"}}
	if got := RoleFor(p, c); got != session.RoleOperator {
		t.Fatalf("got %q, want %q", got, session.RoleOperator)
	}
}

// TestRoleFor_NoMatchFallsBackToViewer proves a user who is allowed to
// log in (passed Authorize) but matches none of the RBAC keys gets
// the least-privileged role, once the provider has opted into RBAC.
func TestRoleFor_NoMatchFallsBackToViewer(t *testing.T) {
	p := ProviderConfig{AdminGroups: []string{"admins-oid"}}
	c := Claims{Groups: []string{"someone-else"}}
	if got := RoleFor(p, c); got != session.RoleViewer {
		t.Fatalf("got %q, want %q", got, session.RoleViewer)
	}
}

// TestRoleFor_AdminTakesPriorityOverOperator proves a user matching
// both admin and operator keys gets the more privileged role.
func TestRoleFor_AdminTakesPriorityOverOperator(t *testing.T) {
	p := ProviderConfig{AdminGroups: []string{"g"}, OperatorGroups: []string{"g"}}
	c := Claims{Groups: []string{"g"}}
	if got := RoleFor(p, c); got != session.RoleAdmin {
		t.Fatalf("got %q, want %q", got, session.RoleAdmin)
	}
}

// TestRoleFor_GroupComparisonIsCaseInsensitive matches Authorize's own
// group-matching rule (Entra object IDs).
func TestRoleFor_GroupComparisonIsCaseInsensitive(t *testing.T) {
	p := ProviderConfig{AdminGroups: []string{"ABCD-1234"}}
	c := Claims{Groups: []string{"abcd-1234"}}
	if got := RoleFor(p, c); got != session.RoleAdmin {
		t.Fatalf("got %q, want %q", got, session.RoleAdmin)
	}
}

// TestRoleFor_NoMatchUsesDefaultRole proves that a provider whose
// claims never carry groups/roles (e.g. Google) can still grant every
// authorized user a role above viewer, by setting DefaultRole. This is
// the only way such a provider can land anywhere but RoleAdmin (no RBAC
// keys set) or RoleViewer (RBAC keys set, nothing ever matches).
func TestRoleFor_NoMatchUsesDefaultRole(t *testing.T) {
	p := ProviderConfig{AdminGroups: []string{"admins-oid"}, DefaultRole: session.RoleOperator}
	c := Claims{} // Google-style: no groups/roles claims at all
	if got := RoleFor(p, c); got != session.RoleOperator {
		t.Fatalf("got %q, want %q", got, session.RoleOperator)
	}
}

// TestRoleFor_DefaultRoleNeverOverridesAnActualMatch proves DefaultRole
// only applies when nothing matched; a user who does match an admin
// group still gets admin even if DefaultRole is set lower.
func TestRoleFor_DefaultRoleNeverOverridesAnActualMatch(t *testing.T) {
	p := ProviderConfig{AdminGroups: []string{"admins-oid"}, DefaultRole: session.RoleViewer}
	c := Claims{Groups: []string{"admins-oid"}}
	if got := RoleFor(p, c); got != session.RoleAdmin {
		t.Fatalf("got %q, want %q", got, session.RoleAdmin)
	}
}

// TestRoleFor_EmptyDefaultRoleKeepsLegacyViewerFallback proves that
// leaving DefaultRole unset preserves the pre-existing behavior exactly.
func TestRoleFor_EmptyDefaultRoleKeepsLegacyViewerFallback(t *testing.T) {
	p := ProviderConfig{AdminGroups: []string{"admins-oid"}}
	c := Claims{Groups: []string{"someone-else"}}
	if got := RoleFor(p, c); got != session.RoleViewer {
		t.Fatalf("got %q, want %q", got, session.RoleViewer)
	}
}
