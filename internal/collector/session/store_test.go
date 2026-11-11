package session

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/collector/db"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newTestStore(t *testing.T) (*Store, *clock) {
	t.Helper()
	database, err := db.Open(filepath.Join(t.TempDir(), "radar.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	return &Store{DB: database, Now: c.now}, c
}

func TestStore_CreateAndLookup(t *testing.T) {
	ctx := context.Background()
	st, _ := newTestStore(t)
	id, s, err := st.Create(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(id) < 43 || len(s.CSRFToken) < 43 {
		t.Fatalf("id/csrf too short: %q %q", id, s.CSRFToken)
	}
	got, ok, err := st.Lookup(ctx, id)
	if err != nil || !ok || got.CSRFToken != s.CSRFToken {
		t.Fatalf("lookup: ok=%v err=%v got=%+v", ok, err, got)
	}
	if _, ok, _ := st.Lookup(ctx, "unknown"); ok {
		t.Fatal("unknown id found")
	}
}

func TestStore_StoresOnlyTheHash(t *testing.T) {
	ctx := context.Background()
	st, _ := newTestStore(t)
	id, _, _ := st.Create(ctx)
	var n int
	st.DB.QueryRow(`SELECT COUNT(*) FROM admin_sessions WHERE id_hash = ?`, id).Scan(&n)
	if n != 0 {
		t.Fatal("raw session id stored in the database")
	}
}

func TestStore_IdleExpiry(t *testing.T) {
	ctx := context.Background()
	st, c := newTestStore(t)
	id, _, _ := st.Create(ctx)
	c.t = c.t.Add(29 * time.Minute)
	if _, ok, _ := st.Lookup(ctx, id); !ok {
		t.Fatal("expired too early")
	}
	c.t = c.t.Add(31 * time.Minute) // 31 min since last activity
	if _, ok, _ := st.Lookup(ctx, id); ok {
		t.Fatal("idle session still valid after 31 minutes")
	}
	var n int
	st.DB.QueryRow(`SELECT COUNT(*) FROM admin_sessions`).Scan(&n)
	if n != 0 {
		t.Fatal("expired session not deleted")
	}
}

func TestStore_AbsoluteExpiry(t *testing.T) {
	ctx := context.Background()
	st, c := newTestStore(t)
	id, _, _ := st.Create(ctx)
	for i := 0; i < 20; i++ { // active every 25 minutes for 8h20
		c.t = c.t.Add(25 * time.Minute)
		st.Lookup(ctx, id)
	}
	if _, ok, _ := st.Lookup(ctx, id); ok {
		t.Fatal("session valid beyond the 8 hour absolute lifetime")
	}
}

func TestStore_DeleteAndDeleteAll(t *testing.T) {
	ctx := context.Background()
	st, _ := newTestStore(t)
	a, _, _ := st.Create(ctx)
	b, _, _ := st.Create(ctx)
	st.Delete(ctx, a)
	if _, ok, _ := st.Lookup(ctx, a); ok {
		t.Fatal("deleted session still valid")
	}
	if _, ok, _ := st.Lookup(ctx, b); !ok {
		t.Fatal("other session removed by Delete")
	}
	st.DeleteAll(ctx)
	if _, ok, _ := st.Lookup(ctx, b); ok {
		t.Fatal("session survived DeleteAll")
	}
}

func TestCookieAttributes(t *testing.T) {
	c := Cookie("abc")
	if c.Name != "__Host-er_session" || c.Value != "abc" || c.Path != "/" || c.Domain != "" ||
		!c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("bad cookie: %+v", c)
	}
	e := ExpiredCookie()
	if e.Name != CookieName || e.MaxAge >= 0 || !e.Secure || e.Path != "/" {
		t.Fatalf("bad expired cookie: %+v", e)
	}
}
