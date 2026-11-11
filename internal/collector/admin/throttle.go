package admin

import (
	"sync"
	"time"
)

// Throttle counts failed logins per key (client address) inside a
// sliding window, in memory. It stops one address from guessing or from
// locking the account for everyone else.
type Throttle struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	fails  map[string][]time.Time
}

// NewThrottle allows limit failures per key within window.
func NewThrottle(limit int, window time.Duration) *Throttle {
	return &Throttle{limit: limit, window: window, fails: map[string][]time.Time{}}
}

func (t *Throttle) recent(key string, now time.Time) []time.Time {
	kept := t.fails[key][:0]
	for _, ts := range t.fails[key] {
		if now.Sub(ts) < t.window {
			kept = append(kept, ts)
		}
	}
	if len(kept) == 0 {
		delete(t.fails, key)
		return nil
	}
	t.fails[key] = kept
	return kept
}

// Blocked reports whether key has used up its failures in the window.
func (t *Throttle) Blocked(key string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.recent(key, now)) >= t.limit
}

// Fail records one failure for key.
func (t *Throttle) Fail(key string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.fails) > 10000 { // bound memory: drop expired entries
		for k := range t.fails {
			t.recent(k, now)
		}
	}
	t.fails[key] = append(t.recent(key, now), now)
}

// Reset forgets key's failures (after a successful login).
func (t *Throttle) Reset(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.fails, key)
}
