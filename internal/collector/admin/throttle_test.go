package admin

import (
	"testing"
	"time"
)

func TestThrottle_BlocksAfterLimitPerKey(t *testing.T) {
	th := NewThrottle(5, 15*time.Minute)
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < 5; i++ {
		if th.Blocked("10.0.0.1", now) {
			t.Fatalf("blocked after %d failures", i)
		}
		th.Fail("10.0.0.1", now)
	}
	if !th.Blocked("10.0.0.1", now) {
		t.Fatal("not blocked after 5 failures")
	}
	if th.Blocked("10.0.0.2", now) {
		t.Fatal("another address blocked")
	}
	if th.Blocked("10.0.0.1", now.Add(15*time.Minute+time.Second)) {
		t.Fatal("still blocked after the window")
	}
}

func TestThrottle_ResetClearsKey(t *testing.T) {
	th := NewThrottle(2, time.Minute)
	now := time.Now()
	th.Fail("a", now)
	th.Fail("a", now)
	th.Reset("a")
	if th.Blocked("a", now) {
		t.Fatal("blocked after reset")
	}
}
