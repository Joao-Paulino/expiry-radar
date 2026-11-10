package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
)

type fakeChecker struct {
	name    string
	records []checker.ExpiryRecord
	err     error
}

func (f *fakeChecker) Name() string { return f.name }
func (f *fakeChecker) Kind() string { return "certificate" }
func (f *fakeChecker) Check(ctx context.Context) ([]checker.ExpiryRecord, error) {
	return f.records, f.err
}

func TestRunner_RunOnce_IsolatesCheckerFailureAndPushesBoth(t *testing.T) {
	var gotBatch checker.Batch
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotBatch)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	okChecker := &fakeChecker{name: "ok-checker", records: []checker.ExpiryRecord{{Source: "a", Name: "b", Kind: "certificate", ExpiresAt: time.Now()}}}
	failChecker := &fakeChecker{name: "fail-checker", err: errors.New("unreachable")}

	r := NewRunner("agent-1", []checker.Checker{okChecker, failChecker}, NewPusher(srv.URL, "t"), NewQueue(filepath.Join(t.TempDir(), "q.jsonl")))
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce should isolate checker failures, got %v", err)
	}
	if len(gotBatch.Results) != 2 {
		t.Fatalf("expected 2 results in the pushed batch, got %d", len(gotBatch.Results))
	}
	var sawFail bool
	for _, res := range gotBatch.Results {
		if res.CheckerName == "fail-checker" {
			sawFail = true
			if res.ErrMsg != "unreachable" {
				t.Fatalf("ErrMsg = %q, want %q", res.ErrMsg, "unreachable")
			}
		}
	}
	if !sawFail {
		t.Fatal("expected fail-checker's result to be included despite its error")
	}
}

// TestRunner_RunOnce_KeepsRecordsEvenWhenCheckerAlsoErrors proves a
// checker that returns BOTH partial records and an error (as
// tls.Checker does for a multi-target run where some targets fail,
// see internal/checker/tls's own PartialFailureKeepsOtherResults
// test) does not have its records silently dropped at the Runner
// level just because ErrMsg is also set.
func TestRunner_RunOnce_KeepsRecordsEvenWhenCheckerAlsoErrors(t *testing.T) {
	var gotBatch checker.Batch
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotBatch)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	partialChecker := &fakeChecker{
		name:    "tls-checker",
		records: []checker.ExpiryRecord{{Source: "a", Name: "b", Kind: "certificate", ExpiresAt: time.Now()}},
		err:     errors.New("one target unreachable"),
	}

	r := NewRunner("agent-1", []checker.Checker{partialChecker}, NewPusher(srv.URL, "t"), NewQueue(filepath.Join(t.TempDir(), "q.jsonl")))
	if err := r.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	if len(gotBatch.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(gotBatch.Results))
	}
	if len(gotBatch.Results[0].Records) != 1 {
		t.Fatalf("expected the partial checker's record to survive, got %+v", gotBatch.Results[0])
	}
	if gotBatch.Results[0].ErrMsg != "one target unreachable" {
		t.Fatalf("ErrMsg = %q, want %q", gotBatch.Results[0].ErrMsg, "one target unreachable")
	}
}

func TestRunner_RunOnce_QueuesOnPushFailure(t *testing.T) {
	unreachableURL := "http://127.0.0.1:1" // nothing listening
	qPath := filepath.Join(t.TempDir(), "q.jsonl")
	r := NewRunner("agent-1", []checker.Checker{&fakeChecker{name: "c", records: []checker.ExpiryRecord{{Source: "a", Name: "b", Kind: "certificate", ExpiresAt: time.Now()}}}}, NewPusher(unreachableURL, "t"), NewQueue(qPath))
	r.RunOnce(context.Background())

	if _, err := os.Stat(qPath); err != nil {
		t.Fatalf("expected queue file to exist after a failed push, got %v", err)
	}
}
