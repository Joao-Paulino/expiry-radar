package rules

import (
	"context"
	"path/filepath"
	"testing"

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
