package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMiddleware_RejectsMissingAndWrongToken(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := Middleware([]string{"good-token"}, inner)

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing token: got %d, want 401", rec.Code)
	}

	req2 := httptest.NewRequest("GET", "/", nil)
	AttachToken(req2, "wrong-token")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: got %d, want 401", rec2.Code)
	}
}

func TestMiddleware_AcceptsValidToken(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := Middleware([]string{"good-token"}, inner)
	req := httptest.NewRequest("GET", "/", nil)
	AttachToken(req, "good-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
}

// A token bound to an agent ID makes that ID available to the handler;
// a shared (unbound) token carries none.
func TestAgentMiddleware_ExposesBoundAgent(t *testing.T) {
	creds := []Credential{{Token: "bound-token-0123456789abcdef0123", AgentID: "web-01"}, {Token: "shared-token-0123456789abcdef012"}}
	var got string
	var bound bool
	h := AgentMiddleware(creds, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, bound = BoundAgent(r.Context())
	}))
	for _, c := range []struct {
		token, want string
		bound       bool
	}{{"bound-token-0123456789abcdef0123", "web-01", true}, {"shared-token-0123456789abcdef012", "", false}} {
		req := httptest.NewRequest("POST", "/ingest", nil)
		req.Header.Set("Authorization", "Bearer "+c.token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != 200 || got != c.want || bound != c.bound {
			t.Errorf("token %s: code %d agent %q bound %v", c.token[:5], w.Code, got, bound)
		}
	}
	req := httptest.NewRequest("POST", "/ingest", nil)
	req.Header.Set("Authorization", "Bearer nope")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("unknown token: %d", w.Code)
	}
}
