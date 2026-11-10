package agent

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
)

func TestQueue_Drain_SendsInOrderAndEmpties(t *testing.T) {
	q := NewQueue(filepath.Join(t.TempDir(), "queue.jsonl"))
	b1 := checker.Batch{AgentID: "1"}
	b2 := checker.Batch{AgentID: "2"}
	q.Enqueue(b1)
	q.Enqueue(b2)

	var got []checker.Batch
	err := q.Drain(context.Background(), func(b checker.Batch) error {
		got = append(got, b)
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 || got[0].AgentID != "1" || got[1].AgentID != "2" {
		t.Fatalf("got %+v", got)
	}

	var secondDrain []checker.Batch
	q.Drain(context.Background(), func(b checker.Batch) error { secondDrain = append(secondDrain, b); return nil })
	if len(secondDrain) != 0 {
		t.Fatalf("expected queue empty after first drain, got %d items", len(secondDrain))
	}
}

func TestQueue_Drain_StopsOnFirstFailureAndKeepsBacklog(t *testing.T) {
	q := NewQueue(filepath.Join(t.TempDir(), "queue.jsonl"))
	q.Enqueue(checker.Batch{AgentID: "1"})
	q.Enqueue(checker.Batch{AgentID: "2"})

	calls := 0
	err := q.Drain(context.Background(), func(b checker.Batch) error {
		calls++
		return errors.New("still unreachable")
	})
	if err == nil {
		t.Fatal("expected Drain to return the send error")
	}
	if calls != 1 {
		t.Fatalf("expected Drain to stop after the first failure, got %d calls", calls)
	}

	var remaining []checker.Batch
	q.Drain(context.Background(), func(b checker.Batch) error { remaining = append(remaining, b); return nil })
	if len(remaining) != 2 {
		t.Fatalf("expected both batches still queued, got %d", len(remaining))
	}
}
