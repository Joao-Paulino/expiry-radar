package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/rules"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/store"
)

type fakeStore struct {
	current []store.StoredRecord
	history []store.StoredRecord
}

func (f *fakeStore) SaveRecords(ctx context.Context, agentID string, records []checker.ExpiryRecord, checkedAt time.Time) error {
	return nil
}

func (f *fakeStore) RecordCheckerHealth(ctx context.Context, checkerName, reportedBy string, checkErr error) error {
	return nil
}

func (f *fakeStore) ListCurrent(ctx context.Context) ([]store.StoredRecord, error) {
	return f.current, nil
}

func (f *fakeStore) History(ctx context.Context, source, name, kind string) ([]store.StoredRecord, error) {
	return f.history, nil
}

func (f *fakeStore) CheckerHealth(ctx context.Context) ([]store.CheckerHealth, error) {
	return nil, nil
}

type fakeRulesStore struct {
	upserted rules.Rule
	rule     rules.Rule
	found    bool
}

func (f *fakeRulesStore) Get(ctx context.Context, source, name, kind string) (rules.Rule, bool, error) {
	return f.rule, f.found, nil
}

func (f *fakeRulesStore) Upsert(ctx context.Context, r rules.Rule) error {
	f.upserted = r
	return nil
}

func (f *fakeRulesStore) List(ctx context.Context) ([]rules.Rule, error) {
	return nil, nil
}

func TestMux_List_Returns200WithRecords(t *testing.T) {
	st := &fakeStore{current: []store.StoredRecord{{ExpiryRecord: checker.ExpiryRecord{Source: "a", Name: "b", Kind: "certificate", ExpiresAt: time.Now().Add(48 * time.Hour)}}}}
	mux := NewMux(st, &fakeRulesStore{})
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "b") {
		t.Fatal("expected record name in rendered page")
	}
}

func TestMux_PostRules_UpsertsAndRedirects(t *testing.T) {
	rs := &fakeRulesStore{}
	mux := NewMux(&fakeStore{}, rs)
	form := url.Values{"source": {"a"}, "name": {"b"}, "kind": {"certificate"}, "muted": {"on"}, "owner": {"joao"}}
	req := httptest.NewRequest("POST", "/rules", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("got %d, want 303", rec.Code)
	}
	if !rs.upserted.Muted || rs.upserted.Owner != "joao" {
		t.Fatalf("got %+v", rs.upserted)
	}
}

func TestMux_ExportJSON_ReturnsValidArray(t *testing.T) {
	st := &fakeStore{current: []store.StoredRecord{{ExpiryRecord: checker.ExpiryRecord{Source: "a", Name: "b", Kind: "certificate", ExpiresAt: time.Now()}}}}
	mux := NewMux(st, &fakeRulesStore{})
	req := httptest.NewRequest("GET", "/export.json", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var decoded []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
}

func TestMux_History_Returns200(t *testing.T) {
	st := &fakeStore{history: []store.StoredRecord{{ExpiryRecord: checker.ExpiryRecord{Source: "a", Name: "b", Kind: "certificate", ExpiresAt: time.Now()}}}}
	mux := NewMux(st, &fakeRulesStore{})
	req := httptest.NewRequest("GET", "/history?source=a&name=b&kind=certificate", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "b") {
		t.Fatal("expected record name in rendered page")
	}
}

func TestMux_ExportCSV_ReturnsCSV(t *testing.T) {
	st := &fakeStore{current: []store.StoredRecord{{ExpiryRecord: checker.ExpiryRecord{Source: "a", Name: "b", Kind: "certificate", ExpiresAt: time.Now()}}}}
	mux := NewMux(st, &fakeRulesStore{})
	req := httptest.NewRequest("GET", "/export.csv", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "source,name,kind") {
		t.Fatalf("expected CSV header, got %q", rec.Body.String())
	}
}
