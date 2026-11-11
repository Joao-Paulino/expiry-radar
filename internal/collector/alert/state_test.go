package alert

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/collector/db"
)

func newStateStore(t *testing.T) *StateStore {
	t.Helper()
	database, err := db.Open(filepath.Join(t.TempDir(), "radar.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	return &StateStore{DB: database, ReminderCritical: 24 * time.Hour}
}

type decision struct{ send, resolved bool }

func decide(t *testing.T, s *StateStore, key string, sev Severity, now time.Time) decision {
	t.Helper()
	send, resolved, err := s.Decide(context.Background(), key, sev, now)
	if err != nil {
		t.Fatal(err)
	}
	if send {
		if err := s.Commit(context.Background(), key, sev, now); err != nil {
			t.Fatal(err)
		}
	}
	return decision{send, resolved}
}

func TestStateStore_Decide(t *testing.T) {
	s := newStateStore(t)
	t0 := time.Unix(1_700_000_000, 0)
	k := "expiry|a:443|a|certificate"
	steps := []struct {
		name string
		sev  Severity
		at   time.Duration
		want decision
	}{
		{"ok with no history stays quiet", SeverityOK, 0, decision{}},
		{"first warning sends", SeverityWarning, time.Hour, decision{send: true}},
		{"same warning is quiet", SeverityWarning, 2 * time.Hour, decision{}},
		{"warning never reminds by default", SeverityWarning, 200 * time.Hour, decision{}},
		{"escalation to critical sends", SeverityCritical, 201 * time.Hour, decision{send: true}},
		{"critical quiet before 24h", SeverityCritical, 224 * time.Hour, decision{}},
		{"critical reminder at 24h", SeverityCritical, 225 * time.Hour, decision{send: true}},
		{"back to ok sends resolved", SeverityOK, 226 * time.Hour, decision{send: true, resolved: true}},
		{"resolved only once", SeverityOK, 227 * time.Hour, decision{}},
	}
	for _, st := range steps {
		if got := decide(t, s, k, st.sev, t0.Add(st.at)); got != st.want {
			t.Fatalf("%s: got %+v, want %+v", st.name, got, st.want)
		}
	}
}

func TestStateStore_WarningReminderWhenConfigured(t *testing.T) {
	s := newStateStore(t)
	s.ReminderWarning = 48 * time.Hour
	t0 := time.Unix(1_700_000_000, 0)
	decide(t, s, "k", SeverityWarning, t0)
	if got := decide(t, s, "k", SeverityWarning, t0.Add(48*time.Hour)); !got.send {
		t.Fatal("warning reminder not sent after 48h")
	}
}

func TestStateStore_SurvivesRestartAndClear(t *testing.T) {
	s := newStateStore(t)
	t0 := time.Unix(1_700_000_000, 0)
	decide(t, s, "k", SeverityCritical, t0)
	restarted := &StateStore{DB: s.DB, ReminderCritical: 24 * time.Hour}
	if got := decide(t, restarted, "k", SeverityCritical, t0.Add(time.Hour)); got.send {
		t.Fatal("alert re-sent after a collector restart")
	}
	if err := restarted.Clear(context.Background(), "k"); err != nil {
		t.Fatal(err)
	}
	if got := decide(t, restarted, "k", SeverityCritical, t0.Add(2*time.Hour)); !got.send {
		t.Fatal("cleared key did not alert again")
	}
}
