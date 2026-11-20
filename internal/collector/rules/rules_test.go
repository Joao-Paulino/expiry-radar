package rules

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/collector/db"
)

func newTestRulesStore(t *testing.T) *SQLite {
	database, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("db.Open failed: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	return NewSQLite(database)
}

func TestSQLite_Upsert_ThenGet(t *testing.T) {
	s := newTestRulesStore(t)
	ctx := context.Background()
	r := Rule{Source: "a", Name: "b", Kind: "certificate", Muted: true, Owner: "joao"}
	if err := s.Upsert(ctx, r); err != nil {
		t.Fatal(err)
	}
	got, found, err := s.Get(ctx, "a", "b", "certificate")
	if err != nil || !found {
		t.Fatalf("Get failed: found=%v err=%v", found, err)
	}
	if got != r {
		t.Fatalf("Get = %+v, want %+v", got, r)
	}
}

// TestSQLite_Upsert_RoundTripsMuteReasonAndUntil proves a mute's
// mandatory reason and optional expiry survive a write/read cycle.
func TestSQLite_Upsert_RoundTripsMuteReasonAndUntil(t *testing.T) {
	s := newTestRulesStore(t)
	ctx := context.Background()
	until := time.Date(2027, 1, 15, 0, 0, 0, 0, time.UTC)
	r := Rule{Source: "a", Name: "b", Kind: "certificate", Muted: true, Owner: "joao",
		MuteReason: "renewing next sprint, ticket OPS-123", MuteUntil: until}
	if err := s.Upsert(ctx, r); err != nil {
		t.Fatal(err)
	}
	got, found, err := s.Get(ctx, "a", "b", "certificate")
	if err != nil || !found {
		t.Fatalf("Get failed: found=%v err=%v", found, err)
	}
	if got.MuteReason != r.MuteReason || !got.MuteUntil.Equal(r.MuteUntil) {
		t.Fatalf("got reason=%q until=%v, want reason=%q until=%v", got.MuteReason, got.MuteUntil, r.MuteReason, r.MuteUntil)
	}
}

// TestRule_ActiveMute proves a mute auto-expires: once MuteUntil is in
// the past, the rule is no longer considered an active mute, without
// anyone having to unmute it by hand.
func TestRule_ActiveMute(t *testing.T) {
	now := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		r    Rule
		want bool
	}{
		{"not muted", Rule{Muted: false}, false},
		{"muted, no expiry", Rule{Muted: true}, true},
		{"muted, expiry in the future", Rule{Muted: true, MuteUntil: now.Add(24 * time.Hour)}, true},
		{"muted, expiry in the past", Rule{Muted: true, MuteUntil: now.Add(-24 * time.Hour)}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.r.ActiveMute(now); got != c.want {
				t.Fatalf("ActiveMute() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestSQLite_Get_NotFound(t *testing.T) {
	s := newTestRulesStore(t)
	_, found, err := s.Get(context.Background(), "missing", "missing", "certificate")
	if err != nil {
		t.Fatal(err)
	}
	if found {
		t.Fatal("expected found=false for a rule that was never set")
	}
}
