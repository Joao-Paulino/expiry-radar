package dashboard

import (
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/collector/admin"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/db"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/session"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/sso"
)

const loginPassword = "correct horse battery staple"

type loginEnv struct {
	auth      *admin.Authenticator
	sessions  *session.Store
	secret    string
	get       http.Handler
	post      http.Handler
	logout    http.Handler
	revokeAll http.Handler
}

func newLoginEnv(t *testing.T, configured bool) *loginEnv {
	t.Helper()
	database, err := db.Open(filepath.Join(t.TempDir(), "radar.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	ctx := context.Background()
	as := &admin.Store{DB: database}
	e := &loginEnv{
		auth:     &admin.Authenticator{Store: as, Now: time.Now},
		sessions: &session.Store{DB: database, Now: time.Now},
	}
	if configured {
		h, _ := admin.HashPassword(loginPassword)
		as.SetPassword(ctx, h)
		e.secret, _ = admin.NewTOTPSecret()
		_, hashes, _ := admin.NewRecoveryCodes()
		as.SetTOTP(ctx, e.secret, hashes)
	}
	e.get, e.post, e.logout, e.revokeAll = LoginHandlers(e.auth, e.sessions, []sso.Button{{Label: "Microsoft", URL: "/auth/microsoft/login"}})
	return e
}

func (e *loginEnv) postLogin(t *testing.T, password, code string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"password": {password}, "code": {code}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	e.post.ServeHTTP(rec, req)
	return rec
}

func sessionCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == session.CookieName {
			return c
		}
	}
	return nil
}

func TestLoginPage_RendersForm(t *testing.T) {
	e := newLoginEnv(t, true)
	rec := httptest.NewRecorder()
	e.get.ServeHTTP(rec, httptest.NewRequest("GET", "/login", nil))
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, `name="password"`) || !strings.Contains(body, `name="code"`) {
		t.Fatalf("code=%d body=%s", rec.Code, body)
	}
}

func TestLoginPost_SuccessSetsFreshSession(t *testing.T) {
	e := newLoginEnv(t, true)
	oldID, _, _ := e.sessions.Create(context.Background())
	code, _ := admin.TOTPCode(e.secret, time.Now().Unix()/30)
	rec := e.postLogin(t, loginPassword, code, session.Cookie(oldID))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Fatalf("code=%d location=%q", rec.Code, rec.Header().Get("Location"))
	}
	c := sessionCookie(rec)
	if c == nil || c.Value == "" || c.Value == oldID {
		t.Fatalf("expected a fresh session cookie, got %+v", c)
	}
	if _, ok, _ := e.sessions.Lookup(context.Background(), c.Value); !ok {
		t.Fatal("new session not stored")
	}
	if _, ok, _ := e.sessions.Lookup(context.Background(), oldID); ok {
		t.Fatal("pre-login session still valid (fixation)")
	}
}

func TestLoginPost_FailureIsGeneric(t *testing.T) {
	for name, configured := range map[string]bool{"bad credentials": true, "not configured": false} {
		e := newLoginEnv(t, configured)
		rec := e.postLogin(t, "wrong password!!", "000000")
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Invalid credentials") {
			t.Errorf("%s: code=%d body=%s", name, rec.Code, rec.Body.String())
		}
		if sessionCookie(rec) != nil {
			t.Errorf("%s: session cookie set on failure", name)
		}
	}
}

func TestLogout_DeletesSession(t *testing.T) {
	e := newLoginEnv(t, true)
	id, _, _ := e.sessions.Create(context.Background())
	req := httptest.NewRequest("POST", "/logout", nil)
	req.AddCookie(session.Cookie(id))
	rec := httptest.NewRecorder()
	e.logout.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("code=%d location=%q", rec.Code, rec.Header().Get("Location"))
	}
	if _, ok, _ := e.sessions.Lookup(context.Background(), id); ok {
		t.Fatal("session survived logout")
	}
	if c := sessionCookie(rec); c == nil || c.MaxAge >= 0 {
		t.Fatalf("cookie not expired: %+v", c)
	}
}

func TestListPage_IncludesCSRFFieldForSessions(t *testing.T) {
	e := newLoginEnv(t, true)
	id, s, _ := e.sessions.Create(context.Background())
	h := session.Middleware(e.sessions, nil, NewMux(&fakeStore{}, &fakeRulesStore{}))
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(session.Cookie(id))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, `name="csrf_token" value="`+s.CSRFToken+`"`) {
		t.Fatalf("CSRF field missing: %s", body)
	}
	if !strings.Contains(body, `action="/logout"`) || !strings.Contains(body, `action="/sessions/revoke-all"`) {
		t.Fatal("logout or revoke-all form missing")
	}
}

// TestLoginPost_PerAddressThrottle proves one address that keeps
// failing is refused without touching the account, while another
// address can still sign in (so an attacker cannot lock the admin out).
func TestLoginPost_PerAddressThrottle(t *testing.T) {
	e := newLoginEnv(t, true)
	attempt := func(addr, password, code string) *httptest.ResponseRecorder {
		form := url.Values{"password": {password}, "code": {code}}
		req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = addr
		rec := httptest.NewRecorder()
		e.post.ServeHTTP(rec, req)
		return rec
	}
	for i := 0; i < PerAddressLimit; i++ {
		attempt("203.0.113.9:4000", "wrong password!!", "000000")
	}
	code, _ := admin.TOTPCode(e.secret, time.Now().Unix()/30)
	if rec := attempt("203.0.113.9:4001", loginPassword, code); sessionCookie(rec) != nil {
		t.Fatal("throttled address could still sign in")
	}
	if rec := attempt("198.51.100.7:5000", loginPassword, code); sessionCookie(rec) == nil {
		t.Fatalf("other address could not sign in: %s", rec.Body.String())
	}
}

func captureLog(t *testing.T) *strings.Builder {
	t.Helper()
	var b strings.Builder
	log.SetOutput(&b)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &b
}

// TestLoginPost_LogsRecoveryCodeUse proves a recovery-code login is
// visible in the audit log (it usually means a lost phone).
func TestLoginPost_LogsRecoveryCodeUse(t *testing.T) {
	e := newLoginEnv(t, true)
	plain, hashes, _ := admin.NewRecoveryCodes()
	e.auth.Store.SetTOTP(context.Background(), e.secret, hashes)
	logs := captureLog(t)
	if rec := e.postLogin(t, loginPassword, plain[0]); sessionCookie(rec) == nil {
		t.Fatal("recovery login failed")
	}
	if !strings.Contains(logs.String(), "recovery code") || !strings.Contains(logs.String(), "7 left") {
		t.Fatalf("log does not mention the recovery code: %q", logs.String())
	}
	if strings.Contains(logs.String(), plain[0]) {
		t.Fatal("recovery code written to the log")
	}
}

func TestLoginPage_ShowsSSOButtons(t *testing.T) {
	e := newLoginEnv(t, true)
	rec := httptest.NewRecorder()
	e.get.ServeHTTP(rec, httptest.NewRequest("GET", "/login", nil))
	if !strings.Contains(rec.Body.String(), `href="/auth/microsoft/login"`) || !strings.Contains(rec.Body.String(), "Microsoft") {
		t.Fatalf("no SSO button: %s", rec.Body.String())
	}
}

// TestRevokeAll_EndsEverySession proves the dashboard can cut access
// for everyone at once (e.g. after removing someone from the IdP group).
func TestRevokeAll_EndsEverySession(t *testing.T) {
	e := newLoginEnv(t, true)
	a, _, _ := e.sessions.Create(context.Background())
	b, _, _ := e.sessions.Create(context.Background())
	req := httptest.NewRequest("POST", "/sessions/revoke-all", nil)
	req.AddCookie(session.Cookie(a))
	rec := httptest.NewRecorder()
	e.revokeAll.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("code=%d location=%q", rec.Code, rec.Header().Get("Location"))
	}
	for _, id := range []string{a, b} {
		if _, ok, _ := e.sessions.Lookup(context.Background(), id); ok {
			t.Fatal("a session survived revoke-all")
		}
	}
}
