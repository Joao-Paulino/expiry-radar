package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/store"
)

type fakeStore struct {
	saved []checker.ExpiryRecord
	health []struct {
		name, reportedBy string
		err              error
	}
}

func (f *fakeStore) SaveRecords(ctx context.Context, agentID string, records []checker.ExpiryRecord) error {
	f.saved = append(f.saved, records...)
	return nil
}
func (f *fakeStore) RecordCheckerHealth(ctx context.Context, name, reportedBy string, err error) error {
	f.health = append(f.health, struct {
		name, reportedBy string
		err               error
	}{name, reportedBy, err})
	return nil
}
func (f *fakeStore) ListCurrent(ctx context.Context) ([]store.StoredRecord, error) { return nil, nil }
func (f *fakeStore) History(ctx context.Context, source, name, kind string) ([]store.StoredRecord, error) {
	return nil, nil
}
func (f *fakeStore) CheckerHealth(ctx context.Context) ([]store.CheckerHealth, error) { return nil, nil }

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
