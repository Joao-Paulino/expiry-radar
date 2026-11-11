package sso

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/collector/db"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/session"
)

type env struct {
	h        *Handlers
	idp      *fakeIdP
	sessions *session.Store
	clock    *clock
	mux      *http.ServeMux
}

func newEnv(t *testing.T, allow ProviderConfig) *env {
	t.Helper()
	database, err := db.Open(filepath.Join(t.TempDir(), "radar.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	idp := newFakeIdP(t)
	secret := filepath.Join(t.TempDir(), "s")
	os.WriteFile(secret, []byte("secret"), 0o600)
	allow.Name, allow.DisplayName, allow.Issuer, allow.ClientID, allow.ClientSecretFile = "test", "Test IdP", idp.srv.URL, "client", secret
	c := &clock{t: time.Now()}
	sessions := &session.Store{DB: database, Now: c.now}
	h := &Handlers{
		Providers: []ProviderConfig{allow}, PublicURL: "https://collector.test",
		Flows: &FlowStore{DB: database, Now: c.now}, Sessions: sessions,
		SessionLifetime: time.Hour, HTTPClient: idp.srv.Client(),
	}
	mux := http.NewServeMux()
	h.Register(mux)
	return &env{h: h, idp: idp, sessions: sessions, clock: c, mux: mux}
}

// start runs /auth/test/login and returns the state, the binding cookie
// and arms the fake IdP with the nonce and PKCE challenge it received.
func (e *env) start(t *testing.T) (string, *http.Cookie) {
	t.Helper()
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, httptest.NewRequest("GET", "/auth/test/login", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("login: code %d body %s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, e.idp.srv.URL+"/authorize?") || queryParam(t, loc, "code_challenge_method") != "S256" {
		t.Fatalf("bad authorize redirect %q", loc)
	}
	if ru, _ := url.QueryUnescape(queryParam(t, loc, "redirect_uri")); ru != "https://collector.test/auth/test/callback" {
		t.Fatalf("redirect_uri %q", ru)
	}
	e.idp.mu.Lock()
	e.idp.nonce = queryParam(t, loc, "nonce")
	e.idp.challenge = queryParam(t, loc, "code_challenge")
	e.idp.mu.Unlock()
	var bind *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == BindCookieName {
			bind = c
		}
	}
	if bind == nil || !bind.Secure || !bind.HttpOnly || bind.SameSite != http.SameSiteLaxMode {
		t.Fatalf("binding cookie missing or weak: %+v", bind)
	}
	return queryParam(t, loc, "state"), bind
}

func (e *env) callback(t *testing.T, state string, bind *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", "/auth/test/callback?code=c1&state="+state, nil)
	if bind != nil {
		req.AddCookie(bind)
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

func sessionFrom(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == session.CookieName && c.Value != "" {
			return c
		}
	}
	return nil
}

func emailAllowed() ProviderConfig {
	return ProviderConfig{AllowedEmails: []string{"joao@example.com"}}
}

func TestCallback_Success(t *testing.T) {
	e := newEnv(t, emailAllowed())
	e.idp.claim = map[string]any{"email": "joao@example.com", "email_verified": true}
	state, bind := e.start(t)
	rec := e.callback(t, state, bind)
	c := sessionFrom(rec)
	if rec.Code != http.StatusOK || c == nil || !strings.Contains(rec.Body.String(), `url=/`) {
		t.Fatalf("code=%d cookie=%v body=%s", rec.Code, c, rec.Body.String())
	}
	if _, ok, _ := e.sessions.Lookup(context.Background(), c.Value); !ok {
		t.Fatal("session not stored")
	}
	e.clock.t = e.clock.t.Add(61 * time.Minute)
	if _, ok, _ := e.sessions.Lookup(context.Background(), c.Value); ok {
		t.Fatal("SSO session outlived its 1h lifetime")
	}
}

func TestCallback_Refusals(t *testing.T) {
	cases := map[string]func(e *env, state *string, bind **http.Cookie){
		"unauthorized user": func(e *env, _ *string, _ **http.Cookie) {
			e.idp.claim = map[string]any{"email": "eve@example.com", "email_verified": true}
		},
		"wrong nonce":            func(e *env, _ *string, _ **http.Cookie) { e.idp.nonce = "other" },
		"wrong audience":         func(e *env, _ *string, _ **http.Cookie) { e.idp.aud = "someone-else" },
		"tampered signature":     func(e *env, _ *string, _ **http.Cookie) { e.idp.badSig = true },
		"missing binding cookie": func(e *env, _ *string, b **http.Cookie) { *b = nil },
		"wrong binding cookie":   func(e *env, _ *string, b **http.Cookie) { (*b).Value = "x" },
		"unknown state":          func(e *env, s *string, _ **http.Cookie) { *s = "nope" },
		"expired flow":           func(e *env, _ *string, _ **http.Cookie) { e.clock.t = e.clock.t.Add(11 * time.Minute) },
	}
	for name, mutate := range cases {
		e := newEnv(t, emailAllowed())
		e.idp.claim = map[string]any{"email": "joao@example.com", "email_verified": true}
		state, bind := e.start(t)
		mutate(e, &state, &bind)
		rec := e.callback(t, state, bind)
		if sessionFrom(rec) != nil || rec.Code != http.StatusForbidden {
			t.Errorf("%s: code=%d, session set=%v", name, rec.Code, sessionFrom(rec) != nil)
		}
	}
}

func TestCallback_StateIsSingleUse(t *testing.T) {
	e := newEnv(t, emailAllowed())
	e.idp.claim = map[string]any{"email": "joao@example.com", "email_verified": true}
	state, bind := e.start(t)
	if sessionFrom(e.callback(t, state, bind)) == nil {
		t.Fatal("first callback failed")
	}
	if rec := e.callback(t, state, bind); sessionFrom(rec) != nil {
		t.Fatal("replayed callback created a session")
	}
}

func TestLogin_UnreachableProviderFailsCleanly(t *testing.T) {
	e := newEnv(t, emailAllowed())
	e.h.Providers[0].Issuer = "https://127.0.0.1:1"
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, httptest.NewRequest("GET", "/auth/test/login", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestButtons(t *testing.T) {
	e := newEnv(t, emailAllowed())
	b := e.h.Buttons()
	if len(b) != 1 || b[0].Label != "Test IdP" || b[0].URL != "/auth/test/login" {
		t.Fatalf("got %+v", b)
	}
}
