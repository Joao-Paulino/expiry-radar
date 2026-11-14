package server_test

import (
	"crypto/tls"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Joao-Paulino/expiry-radar/internal/collector/server"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/sso"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/testhelpers"
)

// TestSSO_Keycloak signs in through a real OpenID Connect provider:
// a Keycloak started by CI with test/keycloak/expiry-realm.json. It
// runs only when EXPIRY_RADAR_E2E_KEYCLOAK holds the realm's issuer
// URL, and the process must trust Keycloak's certificate
// (SSL_CERT_FILE), exactly as a production collector would.
func TestSSO_Keycloak(t *testing.T) {
	issuer := os.Getenv("EXPIRY_RADAR_E2E_KEYCLOAK")
	if issuer == "" {
		t.Skip("set EXPIRY_RADAR_E2E_KEYCLOAK to the Keycloak realm issuer (CI job sso-e2e)")
	}
	dir := t.TempDir()
	certFile, keyFile := testhelpers.WriteSelfSignedCertForTest(t, dir)
	secret := filepath.Join(dir, "kc.secret")
	if err := os.WriteFile(secret, []byte("kc-e2e-secret-not-for-production\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const public = "https://localhost:18443"
	addr, stop, err := testhelpers.StartForTest(server.Config{
		DBPath: filepath.Join(dir, "radar.db"), ListenAddr: "127.0.0.1:18443",
		AuthTokens:  []string{"agent-token-0123456789abcdef0123456789"},
		AdminTokens: []string{"admin-token-0123456789abcdef0123456789"},
		TLSCertFile: certFile, TLSKeyFile: keyFile, PublicURL: public,
		OIDCProviders: []sso.ProviderConfig{{
			Name: "keycloak", DisplayName: "Keycloak", Issuer: issuer,
			ClientID: "expiry-radar", ClientSecretFile: secret,
			AllowedEmails: []string{"alice@example.com", "eve@example.com"},
			AllowedGroups: []string{"radar-admins"},
			AllowedRoles:  []string{"ExpiryRadar.Admin"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	_ = addr

	cases := []struct {
		user, why string
		allowed   bool
	}{
		{"alice", "verified email in allowed_emails", true},
		{"bob", "member of an allowed group", true},
		{"carol", "holds an allowed app role", true},
		{"eve", "email listed but not verified", false},
		{"mallory", "no email, group or role allowed", false},
	}
	for _, c := range cases {
		t.Run(c.user, func(t *testing.T) {
			status, body := signIn(t, public, c.user)
			if c.allowed {
				if status != http.StatusOK || !strings.Contains(body, `data-count="expired"`) {
					t.Fatalf("%s (%s): want the dashboard, got %d: %.300s", c.user, c.why, status, body)
				}
				return
			}
			if status != http.StatusForbidden || !strings.Contains(body, "Sign-in refused") {
				t.Fatalf("%s (%s): want 403 refused, got %d: %.300s", c.user, c.why, status, body)
			}
		})
	}
}

var formAction = regexp.MustCompile(`<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"`)

// signIn plays a browser: the collector's SSO button, Keycloak's login
// form, then wherever the callback leads. It returns the final page.
func signIn(t *testing.T, public, user string) (int, string) {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	// The collector's certificate is self-signed in this test; Keycloak's
	// is checked by the collector itself, not by this "browser".
	browser := &http.Client{Jar: jar, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}

	resp, err := browser.Get(public + "/auth/keycloak/login")
	if err != nil {
		t.Fatal(err)
	}
	page := readAll(t, resp)
	m := formAction.FindStringSubmatch(page)
	if resp.StatusCode != http.StatusOK || m == nil {
		t.Fatalf("Keycloak login form not reached: %d %.300s", resp.StatusCode, page)
	}
	resp, err = browser.PostForm(html.UnescapeString(m[1]), url.Values{
		"username": {user}, "password": {"Passw0rd-" + user}, "credentialId": {""},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "Signed in") {
		return resp.StatusCode, body
	}
	// The callback lands on a "Signed in" page that refreshes to the
	// dashboard; follow it with the session cookie, as a browser would.
	resp, err = browser.Get(public + "/")
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, readAll(t, resp)
}

func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
