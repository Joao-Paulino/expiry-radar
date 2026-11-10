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
	current []store.StoredRecord
}

func (f *fakeStore) SaveRecords(ctx context.Context, agentID string, records []checker.ExpiryRecord) error {
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
func (f *fakeStore) CheckerHealth(ctx context.Context) ([]store.CheckerHealth, error) { return nil, nil }

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
