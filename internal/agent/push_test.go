package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
)

func TestPusher_Push_SendsAuthenticatedJSON(t *testing.T) {
	var gotAuth string
	var gotBatch checker.Batch
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		json.NewDecoder(r.Body).Decode(&gotBatch)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	p := NewPusher(srv.URL, "my-token")
	b := checker.Batch{AgentID: "agent-1", Results: []checker.Result{{CheckerName: "tls-checker"}}}
	if err := p.Push(context.Background(), b); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotAuth != "Bearer my-token" {
		t.Fatalf("Authorization = %q", gotAuth)
	}
	if gotBatch.AgentID != "agent-1" {
		t.Fatalf("AgentID = %q", gotBatch.AgentID)
	}
}

func TestPusher_Push_NonSuccessStatusIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	p := NewPusher(srv.URL, "bad-token")
	if err := p.Push(context.Background(), checker.Batch{}); err == nil {
		t.Fatal("expected an error for a 401 response")
	}
}
