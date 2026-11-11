package session

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const adminToken = "admin-token-0123456789abcdef0123456789"

func handlerRecordingCSRF(got *string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*got = CSRFToken(r.Context())
		w.WriteHeader(http.StatusOK)
	})
}

func TestMiddleware_BearerToken(t *testing.T) {
	st, _ := newTestStore(t)
	var csrf string
	h := Middleware(st, []string{adminToken}, handlerRecordingCSRF(&csrf))
	req := httptest.NewRequest("POST", "/rules", strings.NewReader("muted=on"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || csrf != "" {
		t.Fatalf("bearer POST without CSRF: code=%d csrf=%q", rec.Code, csrf)
	}
}

func TestMiddleware_WrongBearerIs401(t *testing.T) {
	st, _ := newTestStore(t)
	var csrf string
	h := Middleware(st, []string{adminToken}, handlerRecordingCSRF(&csrf))
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer nope")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestMiddleware_SessionGETExposesCSRF(t *testing.T) {
	st, _ := newTestStore(t)
	id, s, _ := st.Create(context.Background())
	var csrf string
	h := Middleware(st, []string{adminToken}, handlerRecordingCSRF(&csrf))
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(Cookie(id))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || csrf != s.CSRFToken {
		t.Fatalf("code=%d csrf=%q want %q", rec.Code, csrf, s.CSRFToken)
	}
}

func TestMiddleware_UnauthenticatedBrowserRedirectsToLogin(t *testing.T) {
	st, _ := newTestStore(t)
	var csrf string
	h := Middleware(st, []string{adminToken}, handlerRecordingCSRF(&csrf))
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("code=%d location=%q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestMiddleware_UnauthenticatedAPIIs401(t *testing.T) {
	st, _ := newTestStore(t)
	var csrf string
	h := Middleware(st, []string{adminToken}, handlerRecordingCSRF(&csrf))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/export.json", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestMiddleware_SessionPOSTRequiresCSRF(t *testing.T) {
	st, _ := newTestStore(t)
	id, s, _ := st.Create(context.Background())
	var csrf string
	h := Middleware(st, []string{adminToken}, handlerRecordingCSRF(&csrf))
	for name, tc := range map[string]struct {
		token string
		want  int
	}{
		"missing": {"", http.StatusForbidden},
		"wrong":   {"bogus", http.StatusForbidden},
		"correct": {s.CSRFToken, http.StatusOK},
	} {
		form := url.Values{"muted": {"on"}}
		if tc.token != "" {
			form.Set("csrf_token", tc.token)
		}
		req := httptest.NewRequest("POST", "/rules", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(Cookie(id))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("%s CSRF: got %d, want %d", name, rec.Code, tc.want)
		}
	}
}

func TestMiddleware_ExpiredSessionCookieIsUnauthenticated(t *testing.T) {
	st, _ := newTestStore(t)
	var csrf string
	h := Middleware(st, []string{adminToken}, handlerRecordingCSRF(&csrf))
	req := httptest.NewRequest("GET", "/export.json", nil)
	req.AddCookie(Cookie("not-a-real-session"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d", rec.Code)
	}
}
