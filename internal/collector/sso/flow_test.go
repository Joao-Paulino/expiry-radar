package sso

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/collector/db"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newFlowStore(t *testing.T) (*FlowStore, *clock) {
	t.Helper()
	database, err := db.Open(filepath.Join(t.TempDir(), "radar.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	return &FlowStore{DB: database, Now: c.now}, c
}

func TestFlowStore_SingleUseAndBoundToProvider(t *testing.T) {
	ctx := context.Background()
	fs, _ := newFlowStore(t)
	state, f, err := fs.Put(ctx, "microsoft")
	if err != nil || len(state) < 40 || len(f.Nonce) < 40 || len(f.Verifier) < 43 {
		t.Fatalf("put: %q %+v %v", state, f, err)
	}
	if _, ok, _ := fs.Take(ctx, state, "google"); ok {
		t.Fatal("flow accepted for another provider")
	}
	if _, ok, _ := fs.Take(ctx, state, "microsoft"); ok {
		t.Fatal("flow still usable after a wrong-provider attempt")
	}
	state, f, _ = fs.Put(ctx, "microsoft")
	got, ok, err := fs.Take(ctx, state, "microsoft")
	if err != nil || !ok || got != f {
		t.Fatalf("take: %+v %v %v", got, ok, err)
	}
	if _, ok, _ := fs.Take(ctx, state, "microsoft"); ok {
		t.Fatal("flow reused")
	}
}

func TestFlowStore_ExpiresAfterTenMinutes(t *testing.T) {
	ctx := context.Background()
	fs, c := newFlowStore(t)
	state, _, _ := fs.Put(ctx, "google")
	c.t = c.t.Add(10*time.Minute + time.Second)
	if _, ok, _ := fs.Take(ctx, state, "google"); ok {
		t.Fatal("expired flow accepted")
	}
	fs.Put(ctx, "google")
	c.t = c.t.Add(11 * time.Minute)
	if n, err := fs.DeleteExpired(ctx); err != nil || n != 1 {
		t.Fatalf("DeleteExpired: %d %v", n, err)
	}
}
