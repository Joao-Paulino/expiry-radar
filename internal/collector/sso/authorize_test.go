package sso

import (
	"encoding/json"
	"strings"
	"testing"
)

func claimsFrom(t *testing.T, js string) Claims {
	t.Helper()
	var c Claims
	if err := json.Unmarshal([]byte(js), &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAuthorize(t *testing.T) {
	p := ProviderConfig{Name: "x", AllowedEmails: []string{"Joao@Example.com"}, AllowedGroups: []string{"g-ops"}, AllowedRoles: []string{"ExpiryRadar.Admin"}}
	cases := []struct {
		name, claims string
		ok           bool
		reason       string
	}{
		{"verified email (case-insensitive)", `{"sub":"1","email":"joao@example.COM","email_verified":true}`, true, ""},
		{"verified email as string", `{"sub":"1","email":"joao@example.com","email_verified":"true"}`, true, ""},
		{"unverified email", `{"sub":"1","email":"joao@example.com","email_verified":false}`, false, "not verified"},
		{"email without verification claim", `{"sub":"1","email":"joao@example.com"}`, false, "not verified"},
		{"group", `{"sub":"1","groups":["other","g-ops"]}`, true, ""},
		{"group id in other case", `{"sub":"1","groups":["G-OPS"]}`, true, ""},
		{"role", `{"sub":"1","roles":["ExpiryRadar.Admin"]}`, true, ""},
		{"groups overage", `{"sub":"1","_claim_names":{"groups":"src1"}}`, false, "overage"},
		{"nobody", `{"sub":"1","email":"x@example.com","email_verified":true,"groups":["g2"],"roles":["r2"]}`, false, "not allowed"},
	}
	for _, c := range cases {
		ok, reason := Authorize(p, claimsFrom(t, c.claims))
		if ok != c.ok || (c.reason != "" && !strings.Contains(reason, c.reason)) {
			t.Errorf("%s: ok=%v reason=%q", c.name, ok, reason)
		}
	}
}
