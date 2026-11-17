package ingest

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// FuzzHandler: whatever an authenticated agent sends, /ingest answers
// with one of the documented statuses and never panics.
func FuzzHandler(f *testing.F) {
	f.Add(`{"agent_id":"a","results":[{"checker_name":"tls","checked_at":"2026-01-01T00:00:00Z","records":[{"source":"tls://x:443","name":"x","kind":"certificate","expires_at":"2027-01-01T00:00:00Z"}]}]}`)
	f.Add(`{"agent_id":"a","results":[{"checker_name":"x","error":"boom","records":null}]}`)
	f.Add(`{"results":[{"checked_at":"9999-12-31T23:59:59Z"}]}`)
	f.Add(`{"agent_id":"` + strings.Repeat("‮", 10) + `"}`)
	f.Add(`[]`)
	f.Add(`null`)
	f.Fuzz(func(t *testing.T, body string) {
		rec := httptest.NewRecorder()
		Handler(&fakeStore{})(rec, httptest.NewRequest("POST", "/ingest", strings.NewReader(body)))
		switch rec.Code {
		case http.StatusNoContent, http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusInternalServerError:
		default:
			t.Fatalf("unexpected status %d for %q", rec.Code, body)
		}
	})
}
