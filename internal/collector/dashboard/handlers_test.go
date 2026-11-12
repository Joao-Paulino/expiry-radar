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
	agents    []store.AgentSeen
	forgotten []string
	current   []store.StoredRecord
	history   []store.StoredRecord
	health    []store.CheckerHealth
}

func (f *fakeStore) SaveResult(ctx context.Context, agentID, checkerName string, records []checker.ExpiryRecord, checkedAt time.Time, complete bool) error {
	return f.SaveRecords(ctx, agentID, records, checkedAt)
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
	return f.health, nil
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

// TestMux_List_ShowsAgents proves the dashboard shows each agent's
// checkers, when they last reported and whether they are failing.
func TestMux_List_ShowsAgents(t *testing.T) {
	seen := time.Date(2026, 11, 11, 9, 30, 0, 0, time.UTC)
	st := &fakeStore{agents: []store.AgentSeen{{AgentID: "web-01", LastSeenAt: seen}}, health: []store.CheckerHealth{
		{CheckerName: "tls", ReportedBy: "web-01", LastSeenAt: seen, ConsecutiveFailures: 4, LastError: "dial timeout"},
	}}
	rec := httptest.NewRecorder()
	NewMux(st, &fakeRulesStore{}).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	body := rec.Body.String()
	for _, want := range []string{"Agents", "web-01", "tls", "2026-11-11 09:30", "4", "dial timeout"} {
		if !strings.Contains(body, want) {
			t.Errorf("agents section missing %q", want)
		}
	}
}

func (f *fakeStore) TouchAgent(ctx context.Context, agentID string) error { return nil }
func (f *fakeStore) Agents(ctx context.Context) ([]store.AgentSeen, error) {
	return f.agents, nil
}
func (f *fakeStore) ForgetAgent(ctx context.Context, agentID string) error {
	f.forgotten = append(f.forgotten, agentID)
	return nil
}

// TestMux_ForgetAgent proves a decommissioned agent can be removed from
// the dashboard, which stops its alerts.
func TestMux_ForgetAgent(t *testing.T) {
	st := &fakeStore{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/agents/forget", strings.NewReader("agent_id=old-web"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	NewMux(st, &fakeRulesStore{}).ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || len(st.forgotten) != 1 || st.forgotten[0] != "old-web" {
		t.Fatalf("code=%d forgotten=%v", rec.Code, st.forgotten)
	}
	st2 := &fakeStore{agents: []store.AgentSeen{{AgentID: "web-01", LastSeenAt: time.Now()}}}
	rec = httptest.NewRecorder()
	NewMux(st2, &fakeRulesStore{}).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(rec.Body.String(), `action="/agents/forget"`) {
		t.Fatal("no Forget button on the dashboard")
	}
}

// An informational record (inactive access key) says so on the page,
// or it would look like an overdue key that never alerts.
func TestMux_List_ShowsStatus(t *testing.T) {
	st := &fakeStore{current: []store.StoredRecord{{ExpiryRecord: checker.ExpiryRecord{Source: "aws://iam/1/user/bob/access_key_1", Name: "bob · key 1",
		Kind: "access_key", ExpiresAt: time.Now().Add(-48 * time.Hour), Metadata: map[string]string{"status": "inactive", "alerts": "off"}}}}}
	rec := httptest.NewRecorder()
	NewMux(st, &fakeRulesStore{}).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(rec.Body.String(), "inactive (no alerts)") {
		t.Fatal("status not shown")
	}
}
