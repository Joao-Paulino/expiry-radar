package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/audit"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/db"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/rules"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/session"
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
	mux := NewMux(st, &fakeRulesStore{}, nil)
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
	mux := NewMux(&fakeStore{}, rs, nil)
	form := url.Values{"source": {"a"}, "name": {"b"}, "kind": {"certificate"}, "muted": {"on"}, "owner": {"joao"},
		"mute_reason": {"renewing next sprint, ticket OPS-123"}, "mute_until": {"2027-01-15"}}
	req := httptest.NewRequest("POST", "/rules", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(session.WithRole(req.Context(), session.RoleOperator))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("got %d, want 303", rec.Code)
	}
	if !rs.upserted.Muted || rs.upserted.Owner != "joao" {
		t.Fatalf("got %+v", rs.upserted)
	}
	if rs.upserted.MuteReason != "renewing next sprint, ticket OPS-123" {
		t.Fatalf("MuteReason = %q", rs.upserted.MuteReason)
	}
	wantUntil := time.Date(2027, 1, 15, 0, 0, 0, 0, time.UTC)
	if !rs.upserted.MuteUntil.Equal(wantUntil) {
		t.Fatalf("MuteUntil = %v, want %v", rs.upserted.MuteUntil, wantUntil)
	}
}

// TestMux_PostRules_InvalidMuteUntilDoesNotEchoInput proves a bad
// mute_until value gets a generic error, not one that echoes the raw
// input back in the response (ZAP flagged this as a disclosure risk:
// an attacker-controlled value reflected verbatim in an error body).
func TestMux_PostRules_InvalidMuteUntilDoesNotEchoInput(t *testing.T) {
	rs := &fakeRulesStore{}
	mux := NewMux(&fakeStore{}, rs, nil)
	payload := "<script>very-unusual-marker-xyz</script>"
	form := url.Values{"source": {"a"}, "name": {"b"}, "kind": {"certificate"}, "muted": {"on"},
		"mute_reason": {"r"}, "mute_until": {payload}}
	req := httptest.NewRequest("POST", "/rules", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(session.WithRole(req.Context(), session.RoleOperator))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", rec.Code)
	}
	if strings.Contains(rec.Body.String(), payload) {
		t.Fatalf("response echoes the raw input back: %s", rec.Body.String())
	}
}

// TestMux_PostRules_MuteWithoutReasonIsRejected proves a mute is
// refused unless the caller states why, so the audit log and the
// dashboard always show a reason for every active mute.
func TestMux_PostRules_MuteWithoutReasonIsRejected(t *testing.T) {
	rs := &fakeRulesStore{}
	mux := NewMux(&fakeStore{}, rs, nil)
	form := url.Values{"source": {"a"}, "name": {"b"}, "kind": {"certificate"}, "muted": {"on"}}
	req := httptest.NewRequest("POST", "/rules", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(session.WithRole(req.Context(), session.RoleOperator))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", rec.Code)
	}
	if rs.upserted != (rules.Rule{}) {
		t.Fatalf("expected no upsert, got %+v", rs.upserted)
	}
}

// TestMux_PostRules_UnmutingClearsReasonAndUntil proves turning a
// mute off drops its stale reason/expiry rather than leaving them
// behind for the next mute.
func TestMux_PostRules_UnmutingClearsReasonAndUntil(t *testing.T) {
	rs := &fakeRulesStore{}
	mux := NewMux(&fakeStore{}, rs, nil)
	form := url.Values{"source": {"a"}, "name": {"b"}, "kind": {"certificate"}, "owner": {"joao"}}
	req := httptest.NewRequest("POST", "/rules", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(session.WithRole(req.Context(), session.RoleOperator))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("got %d, want 303", rec.Code)
	}
	if rs.upserted.Muted || rs.upserted.MuteReason != "" || !rs.upserted.MuteUntil.IsZero() {
		t.Fatalf("got %+v, want unmuted with reason/until cleared", rs.upserted)
	}
}

// TestMux_PostRules_WritesAuditEntry proves a mute change is
// recorded under the authenticated actor, with the reason, for a
// later "who did what" view.
func TestMux_PostRules_WritesAuditEntry(t *testing.T) {
	database, err := db.Open(filepath.Join(t.TempDir(), "radar.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	a := &audit.Store{DB: database, Now: time.Now}
	rs := &fakeRulesStore{}
	mux := NewMux(&fakeStore{}, rs, a)

	form := url.Values{"source": {"a"}, "name": {"b"}, "kind": {"certificate"}, "muted": {"on"}, "mute_reason": {"renewing"}}
	req := httptest.NewRequest("POST", "/rules", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(session.WithRole(req.Context(), session.RoleOperator))
	req = req.WithContext(session.WithActor(req.Context(), "alice@example.com"))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("got %d, want 303", rec.Code)
	}

	entries, err := a.List(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Actor != "alice@example.com" || entries[0].Action != "mute" ||
		entries[0].Target != "a|b|certificate" || entries[0].Reason != "renewing" {
		t.Fatalf("got entries %+v", entries)
	}
}

// TestMux_PostRules_OwnerOnlyChangeDoesNotLogSpuriousUnmute proves
// saving just an owner on a never-muted item logs an "owner" entry
// only, not a false "unmute" (the item was never muted to begin with).
func TestMux_PostRules_OwnerOnlyChangeDoesNotLogSpuriousUnmute(t *testing.T) {
	database, err := db.Open(filepath.Join(t.TempDir(), "radar.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	a := &audit.Store{DB: database, Now: time.Now}
	rs := rules.NewSQLite(database)
	mux := NewMux(&fakeStore{}, rs, a)

	form := url.Values{"source": {"a"}, "name": {"b"}, "kind": {"certificate"}, "owner": {"joao"}}
	req := httptest.NewRequest("POST", "/rules", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(session.WithRole(req.Context(), session.RoleOperator))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("got %d, want 303", rec.Code)
	}

	entries, err := a.List(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Action != "owner" {
		t.Fatalf("got entries %+v, want exactly one \"owner\" entry", entries)
	}
}

// TestMux_PostRules_ExtendingAnActiveMuteIsLogged proves changing the
// reason or expiry of an already-muted item is recorded too, so a
// mute can't be silently prolonged without a trace.
func TestMux_PostRules_ExtendingAnActiveMuteIsLogged(t *testing.T) {
	database, err := db.Open(filepath.Join(t.TempDir(), "radar.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	a := &audit.Store{DB: database, Now: time.Now}
	rs := rules.NewSQLite(database)
	mux := NewMux(&fakeStore{}, rs, a)

	post := func(until string) {
		form := url.Values{"source": {"a"}, "name": {"b"}, "kind": {"certificate"}, "muted": {"on"}, "mute_reason": {"renewing"}}
		if until != "" {
			form.Set("mute_until", until)
		}
		req := httptest.NewRequest("POST", "/rules", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req = req.WithContext(session.WithRole(req.Context(), session.RoleOperator))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("got %d, want 303", rec.Code)
		}
	}
	post("2027-01-01")   // first mute
	post("2027-06-01")   // extend the expiry while still muted

	entries, err := a.List(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d audit entries, want 2 (initial mute + the extension)", len(entries))
	}
}

func TestMux_ExportJSON_ReturnsValidArray(t *testing.T) {
	st := &fakeStore{current: []store.StoredRecord{{ExpiryRecord: checker.ExpiryRecord{Source: "a", Name: "b", Kind: "certificate", ExpiresAt: time.Now()}}}}
	mux := NewMux(st, &fakeRulesStore{}, nil)
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
	mux := NewMux(st, &fakeRulesStore{}, nil)
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
	mux := NewMux(st, &fakeRulesStore{}, nil)
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
	NewMux(st, &fakeRulesStore{}, nil).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
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

// TestMux_PostRules_ViewerIsForbidden proves a viewer cannot mute or
// re-own anything; RBAC gates this route at operator and above.
func TestMux_PostRules_ViewerIsForbidden(t *testing.T) {
	rs := &fakeRulesStore{}
	mux := NewMux(&fakeStore{}, rs, nil)
	form := url.Values{"source": {"a"}, "name": {"b"}, "kind": {"certificate"}, "owner": {"joao"}}
	req := httptest.NewRequest("POST", "/rules", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(session.WithRole(req.Context(), session.RoleViewer))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403", rec.Code)
	}
	if rs.upserted != (rules.Rule{}) {
		t.Fatal("a forbidden request still upserted a rule")
	}
}

// TestMux_ForgetAgent_OperatorIsForbidden proves forgetting an agent
// needs the admin role: it is destructive (the agent's whole history
// of checker health disappears), unlike muting or re-owning.
func TestMux_ForgetAgent_OperatorIsForbidden(t *testing.T) {
	st := &fakeStore{}
	req := httptest.NewRequest("POST", "/agents/forget", strings.NewReader("agent_id=old-web"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(session.WithRole(req.Context(), session.RoleOperator))
	rec := httptest.NewRecorder()
	NewMux(st, &fakeRulesStore{}, nil).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403", rec.Code)
	}
	if len(st.forgotten) != 0 {
		t.Fatal("a forbidden request still forgot the agent")
	}
}

// TestMux_ForgetAgent_WritesAuditEntry proves forgetting an agent is
// recorded, since it is a destructive, admin-only action.
func TestMux_ForgetAgent_WritesAuditEntry(t *testing.T) {
	database, err := db.Open(filepath.Join(t.TempDir(), "radar.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	a := &audit.Store{DB: database, Now: time.Now}
	st := &fakeStore{}
	req := httptest.NewRequest("POST", "/agents/forget", strings.NewReader("agent_id=old-web"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(session.WithRole(req.Context(), session.RoleAdmin))
	req = req.WithContext(session.WithActor(req.Context(), "admin"))
	rec := httptest.NewRecorder()
	NewMux(st, &fakeRulesStore{}, a).ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("got %d, want 303", rec.Code)
	}
	entries, err := a.List(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Actor != "admin" || entries[0].Action != "forget_agent" || entries[0].Target != "old-web" {
		t.Fatalf("got entries %+v", entries)
	}
}

// TestMux_ForgetAgent proves a decommissioned agent can be removed from
// the dashboard, which stops its alerts.
func TestMux_ForgetAgent(t *testing.T) {
	st := &fakeStore{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/agents/forget", strings.NewReader("agent_id=old-web"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(session.WithRole(req.Context(), session.RoleAdmin))
	NewMux(st, &fakeRulesStore{}, nil).ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || len(st.forgotten) != 1 || st.forgotten[0] != "old-web" {
		t.Fatalf("code=%d forgotten=%v", rec.Code, st.forgotten)
	}
	st2 := &fakeStore{agents: []store.AgentSeen{{AgentID: "web-01", LastSeenAt: time.Now()}}}
	rec = httptest.NewRecorder()
	NewMux(st2, &fakeRulesStore{}, nil).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
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
	NewMux(st, &fakeRulesStore{}, nil).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(rec.Body.String(), "inactive (no alerts)") {
		t.Fatal("status not shown")
	}
}
