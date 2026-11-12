package alert

import (
	"context"
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
	return nil, nil
}
func (f *fakeStore) CheckerHealth(ctx context.Context) ([]store.CheckerHealth, error) {
	return f.health, nil
}

type fakeRulesStore struct {
	rule  rules.Rule
	found bool
}

func (f *fakeRulesStore) Get(ctx context.Context, source, name, kind string) (rules.Rule, bool, error) {
	if f.found || f.rule != (rules.Rule{}) {
		return f.rule, true, nil
	}
	return rules.Rule{}, false, nil
}
func (f *fakeRulesStore) Upsert(ctx context.Context, r rules.Rule) error { return nil }
func (f *fakeRulesStore) List(ctx context.Context) ([]rules.Rule, error) { return nil, nil }

func TestEvaluate_SeverityByDaysRemaining(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	th := DefaultThresholds()
	cases := []struct {
		days int
		want Severity
	}{
		{40, "ok"}, {30, "warning"}, {10, "warning"}, {7, "critical"}, {0, "critical"}, {-5, "critical"},
	}
	for _, c := range cases {
		rec := store.StoredRecord{ExpiryRecord: checker.ExpiryRecord{Kind: "certificate", ExpiresAt: now.AddDate(0, 0, c.days)}}
		if got := Evaluate(rec, now, th); got != c.want {
			t.Errorf("days=%d: got %q, want %q", c.days, got, c.want)
		}
	}
}

func TestEngine_Evaluate_MutedRecordStillReturnedButMarkedMuted(t *testing.T) {
	st := &fakeStore{current: []store.StoredRecord{{ExpiryRecord: checker.ExpiryRecord{Source: "a", Name: "b", Kind: "certificate", ExpiresAt: time.Now().Add(1 * time.Hour)}}}}
	rs := &fakeRulesStore{rule: rules.Rule{Source: "a", Name: "b", Kind: "certificate", Muted: true}, found: true}
	e := &Engine{Store: st, Rules: rs, Thresholds: DefaultThresholds()}
	notifications, err := e.Evaluate(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(notifications) != 1 {
		t.Fatalf("expected the muted record to still appear, got %d", len(notifications))
	}
	if !notifications[0].Muted {
		t.Fatal("expected Muted=true")
	}
	if notifications[0].Severity != "critical" {
		t.Fatalf("Severity = %q, want critical", notifications[0].Severity)
	}
}

func healthOnly(ns []Notification) map[string]Notification {
	m := map[string]Notification{}
	for _, n := range ns {
		if n.Type != TypeExpiry {
			m[n.Key()] = n
		}
	}
	return m
}

// TestEngine_Evaluate_CheckerFailedAndAgentSilent proves health turns
// into notifications at the configured boundaries, per agent.
func TestEngine_Evaluate_CheckerFailedAndAgentSilent(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	st := &fakeStore{agents: []store.AgentSeen{
		{AgentID: "web-01", LastSeenAt: now.Add(-time.Hour)}, {AgentID: "web-02", LastSeenAt: now.Add(-time.Hour)},
		{AgentID: "web-03", LastSeenAt: now.Add(-3*time.Hour - time.Minute)}, {AgentID: "web-04", LastSeenAt: now.Add(-3 * time.Hour)},
	}, health: []store.CheckerHealth{
		{CheckerName: "tls", ReportedBy: "web-01", LastSeenAt: now.Add(-time.Hour), ConsecutiveFailures: 3, LastError: "timeout"},
		{CheckerName: "tls", ReportedBy: "web-02", LastSeenAt: now.Add(-time.Hour), ConsecutiveFailures: 2},
		{CheckerName: "tls", ReportedBy: "web-03", LastSeenAt: now.Add(-3*time.Hour - time.Minute)},
		{CheckerName: "tls", ReportedBy: "web-04", LastSeenAt: now.Add(-3 * time.Hour)},
	}}
	e := &Engine{Store: st, Rules: &fakeRulesStore{}, Thresholds: DefaultThresholds(), FailThreshold: 3, StaleAfter: 3 * time.Hour}
	ns, err := e.Evaluate(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	h := healthOnly(ns)
	want := map[string]Severity{
		"checker|web-01|tls": SeverityCritical, // 3 failures = threshold
		"checker|web-02|tls": SeverityOK,
		"checker|web-03|tls": SeverityOK,
		"checker|web-04|tls": SeverityOK,
		"agent|web-01":       SeverityOK,
		"agent|web-02":       SeverityOK,
		"agent|web-03":       SeverityCritical, // silent > 3h
		"agent|web-04":       SeverityOK,       // exactly 3h
	}
	for k, sev := range want {
		n, ok := h[k]
		if !ok || n.Severity != sev {
			t.Errorf("%s: got %+v (present=%v), want %s", k, n, ok, sev)
		}
	}
	if n := h["checker|web-01|tls"]; n.Type != TypeCheckerFailed || n.Agent != "web-01" || n.Checker != "tls" || n.Detail != "timeout" {
		t.Errorf("checker notification fields: %+v", n)
	}
	if n := h["agent|web-03"]; n.Type != TypeAgentSilent || n.Agent != "web-03" {
		t.Errorf("agent notification fields: %+v", n)
	}
}

func TestNotification_KeyForExpiry(t *testing.T) {
	n := Notification{Type: TypeExpiry, Record: store.StoredRecord{ExpiryRecord: checker.ExpiryRecord{Source: "a:443", Name: "a", Kind: "certificate"}}}
	if n.Key() != "expiry|a:443|a|certificate" {
		t.Fatalf("got %q", n.Key())
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

// TestEngine_Evaluate_SilenceUsesAgentLastSeen proves an agent that
// reports batches with no checker results is not "silent", and one
// with no checkers that stops reporting still alerts.
func TestEngine_Evaluate_SilenceUsesAgentLastSeen(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	st := &fakeStore{
		agents: []store.AgentSeen{{AgentID: "empty-ok", LastSeenAt: now.Add(-time.Minute)}, {AgentID: "empty-dead", LastSeenAt: now.Add(-5 * time.Hour)}},
		health: []store.CheckerHealth{{CheckerName: "tls", ReportedBy: "empty-ok", LastSeenAt: now.Add(-10 * time.Hour)}},
	}
	e := &Engine{Store: st, Rules: &fakeRulesStore{}, Thresholds: DefaultThresholds(), StaleAfter: 3 * time.Hour}
	ns, _ := e.Evaluate(context.Background(), now)
	h := healthOnly(ns)
	if h["agent|empty-ok"].Severity != SeverityOK || h["agent|empty-dead"].Severity != SeverityCritical {
		t.Fatalf("got %+v", h)
	}
}

// A record a checker marks informational (metadata alerts=off, e.g. an
// inactive AWS access key) is listed but never alerts.
func TestEngine_Evaluate_InformationalRecordNeverAlerts(t *testing.T) {
	st := &fakeStore{current: []store.StoredRecord{{ExpiryRecord: checker.ExpiryRecord{Source: "aws://iam/1/user/bob/access_key_1", Name: "bob · key 1",
		Kind: "access_key", ExpiresAt: time.Now().Add(-48 * time.Hour), Metadata: map[string]string{"status": "inactive", "alerts": "off"}}}}}
	e := &Engine{Store: st, Rules: &fakeRulesStore{}, Thresholds: DefaultThresholds()}
	ns, err := e.Evaluate(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(ns) != 1 || ns[0].Severity != SeverityOK {
		t.Fatalf("informational record alerted: %+v", ns)
	}
}

// Only access keys may be informational: a record of another kind with
// alerts=off (any agent can send metadata) still alerts.
func TestEngine_Evaluate_AlertsOffOnlyForAccessKeys(t *testing.T) {
	st := &fakeStore{current: []store.StoredRecord{{ExpiryRecord: checker.ExpiryRecord{Source: "s", Name: "n", Kind: "certificate",
		ExpiresAt: time.Now().Add(-time.Hour), Metadata: map[string]string{"alerts": "off"}}}}}
	e := &Engine{Store: st, Rules: &fakeRulesStore{}, Thresholds: DefaultThresholds()}
	ns, _ := e.Evaluate(context.Background(), time.Now())
	if len(ns) != 1 || ns[0].Severity != SeverityCritical {
		t.Fatalf("certificate silenced by alerts=off: %+v", ns)
	}
}
