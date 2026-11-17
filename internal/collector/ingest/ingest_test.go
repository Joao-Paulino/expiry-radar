package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/auth"
	"github.com/Joao-Paulino/expiry-radar/internal/checker"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/store"
)

type fakeStore struct {
	agents    []store.AgentSeen
	forgotten []string
	touched   []string
	saved     []checker.ExpiryRecord
	runs      []string // "agent/checker/complete" per SaveResult call
	checked   []time.Time
	health    []struct {
		name, reportedBy string
		err              error
	}
}

func (f *fakeStore) SaveRecords(ctx context.Context, agentID string, records []checker.ExpiryRecord, checkedAt time.Time) error {
	f.saved = append(f.saved, records...)
	return nil
}
func (f *fakeStore) SaveResult(ctx context.Context, agentID, checkerName string, records []checker.ExpiryRecord, checkedAt time.Time, complete bool) error {
	f.saved = append(f.saved, records...)
	f.runs = append(f.runs, fmt.Sprintf("%s/%s/%v", agentID, checkerName, complete))
	f.checked = append(f.checked, checkedAt)
	return nil
}
func (f *fakeStore) RecordCheckerHealth(ctx context.Context, name, reportedBy string, err error) error {
	f.health = append(f.health, struct {
		name, reportedBy string
		err              error
	}{name, reportedBy, err})
	return nil
}
func (f *fakeStore) ListCurrent(ctx context.Context) ([]store.StoredRecord, error) { return nil, nil }
func (f *fakeStore) History(ctx context.Context, source, name, kind string) ([]store.StoredRecord, error) {
	return nil, nil
}
func (f *fakeStore) CheckerHealth(ctx context.Context) ([]store.CheckerHealth, error) {
	return nil, nil
}

func TestHandler_ValidBatch_SavesRecordsAndHealth(t *testing.T) {
	fs := &fakeStore{}
	h := Handler(fs)
	batch := checker.Batch{AgentID: "agent-1", Results: []checker.Result{
		{CheckerName: "tls-checker", Records: []checker.ExpiryRecord{{Source: "a", Name: "b", Kind: "certificate", ExpiresAt: time.Now()}}},
		{CheckerName: "other-checker", ErrMsg: "connection refused"},
	}}
	body, _ := json.Marshal(batch)
	req := httptest.NewRequest("POST", "/ingest", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("got %d, want 204", rec.Code)
	}
	if len(fs.saved) != 1 {
		t.Fatalf("expected 1 saved record, got %d", len(fs.saved))
	}
	if len(fs.health) != 2 {
		t.Fatalf("expected 2 health updates, got %d", len(fs.health))
	}
}

// TestHandler_PartialCheckerFailure_StillSavesTheRecords proves a
// Result that carries both Records and a non-empty ErrMsg (a checker
// that found some things and failed on others — see
// internal/checker/tls's own PartialFailureKeepsOtherResults test and
// agent's KeepsRecordsEvenWhenCheckerAlsoErrors test) still has its
// records saved, instead of being dropped just because ErrMsg is set.
func TestHandler_PartialCheckerFailure_StillSavesTheRecords(t *testing.T) {
	fs := &fakeStore{}
	h := Handler(fs)
	batch := checker.Batch{AgentID: "agent-1", Results: []checker.Result{
		{
			CheckerName: "tls-checker",
			Records:     []checker.ExpiryRecord{{Source: "a", Name: "b", Kind: "certificate", ExpiresAt: time.Now()}},
			ErrMsg:      "one target unreachable",
		},
	}}
	body, _ := json.Marshal(batch)
	req := httptest.NewRequest("POST", "/ingest", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("got %d, want 204", rec.Code)
	}
	if len(fs.saved) != 1 {
		t.Fatalf("expected the partial result's record to be saved, got %d", len(fs.saved))
	}
	if len(fs.health) != 1 || fs.health[0].err == nil {
		t.Fatalf("expected a checker-health error to be recorded too, got %+v", fs.health)
	}
}

func TestHandler_MalformedJSON_Returns400(t *testing.T) {
	h := Handler(&fakeStore{})
	req := httptest.NewRequest("POST", "/ingest", strings.NewReader("{not json"))
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", rec.Code)
	}
}

func (f *fakeStore) TouchAgent(ctx context.Context, agentID string) error {
	f.touched = append(f.touched, agentID)
	return nil
}
func (f *fakeStore) Agents(ctx context.Context) ([]store.AgentSeen, error) {
	return f.agents, nil
}
func (f *fakeStore) ForgetAgent(ctx context.Context, agentID string) error {
	f.forgotten = append(f.forgotten, agentID)
	return nil
}

// TestHandler_EmptyBatchStillMarksAgentSeen proves an agent with no
// checker results is still known to be alive.
func TestHandler_EmptyBatchStillMarksAgentSeen(t *testing.T) {
	st := &fakeStore{}
	body := strings.NewReader(`{"agent_id":"web-09","results":[]}`)
	rec := httptest.NewRecorder()
	Handler(st).ServeHTTP(rec, httptest.NewRequest("POST", "/ingest", body))
	if rec.Code != 204 || len(st.touched) != 1 || st.touched[0] != "web-09" {
		t.Fatalf("code=%d touched=%v", rec.Code, st.touched)
	}
}

// Every result is saved as a run, also one with no records (all items
// gone), and only an error-free run counts as complete.
func TestHandler_EveryResultIsARun(t *testing.T) {
	fs := &fakeStore{}
	batch := checker.Batch{AgentID: "agent-1", Results: []checker.Result{
		{CheckerName: "vault", CheckedAt: time.Now()},
		{CheckerName: "azure", ErrMsg: "vault kv-x: 403", CheckedAt: time.Now(),
			Records: []checker.ExpiryRecord{{Source: "a", Name: "b", Kind: "secret", ExpiresAt: time.Now()}}},
	}}
	body, _ := json.Marshal(batch)
	rec := httptest.NewRecorder()
	Handler(fs)(rec, httptest.NewRequest("POST", "/ingest", bytes.NewReader(body)))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("got %d", rec.Code)
	}
	if fmt.Sprint(fs.runs) != "[agent-1/vault/true agent-1/azure/false]" {
		t.Fatalf("runs: %v", fs.runs)
	}
}

// An agent clock far ahead must not push the collector's notion of
// "latest run" into the future (it would hide new items until then).
func TestHandler_FutureCheckedAtClamped(t *testing.T) {
	fs := &fakeStore{}
	batch := checker.Batch{AgentID: "agent-1", Results: []checker.Result{{CheckerName: "vault", CheckedAt: time.Now().Add(365 * 24 * time.Hour)}}}
	body, _ := json.Marshal(batch)
	Handler(fs)(httptest.NewRecorder(), httptest.NewRequest("POST", "/ingest", bytes.NewReader(body)))
	if len(fs.checked) != 1 || fs.checked[0].After(time.Now().Add(6*time.Minute)) {
		t.Fatalf("future checked_at stored: %v", fs.checked)
	}
}

// TestHandler_OversizedBodyRejected: an authenticated but faulty or
// hostile agent must not make the collector buffer an unbounded body.
func TestHandler_OversizedBodyRejected(t *testing.T) {
	st := &fakeStore{}
	big := `{"agent_id":"a","results":[{"checker_name":"x","records":[],"error":"` + strings.Repeat("x", MaxBodyBytes) + `"}]}`
	rec := httptest.NewRecorder()
	Handler(st)(rec, httptest.NewRequest("POST", "/ingest", strings.NewReader(big)))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("got %d, want 413", rec.Code)
	}
	if len(st.touched) != 0 {
		t.Fatal("nothing may be stored from a rejected body")
	}
}

// A token bound to an agent may only report as that agent (pentest
// BUSL-02): otherwise one compromised host could retire every other
// agent's items with empty complete runs.
func TestHandler_BoundTokenCannotImpersonate(t *testing.T) {
	post := func(st *fakeStore, body string) int {
		req := httptest.NewRequest("POST", "/ingest", strings.NewReader(body))
		req = req.WithContext(auth.WithBoundAgent(req.Context(), "web-01"))
		rec := httptest.NewRecorder()
		Handler(st)(rec, req)
		return rec.Code
	}
	st := &fakeStore{}
	if code := post(st, `{"agent_id":"db-01","results":[{"checker_name":"tls-checker","checked_at":"2026-01-01T00:00:00Z"}]}`); code != http.StatusForbidden {
		t.Fatalf("impersonation: got %d, want 403", code)
	}
	if len(st.touched) != 0 || len(st.runs) != 0 {
		t.Fatalf("nothing may be stored for a refused batch: %+v %+v", st.touched, st.runs)
	}
	if code := post(st, `{"agent_id":"web-01","results":[]}`); code != http.StatusNoContent {
		t.Fatalf("own id: got %d", code)
	}
	st = &fakeStore{}
	if code := post(st, `{"results":[{"checker_name":"tls-checker","checked_at":"2026-01-01T00:00:00Z"}]}`); code != http.StatusNoContent || len(st.touched) != 1 || st.touched[0] != "web-01" {
		t.Fatalf("missing agent_id must default to the bound one: %d %v", code, st.touched)
	}
}
