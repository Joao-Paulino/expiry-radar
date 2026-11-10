package agent

import (
	"context"
	"log"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
	"github.com/Joao-Paulino/expiry-radar/internal/logging"
)

// Runner runs a set of Checkers on each RunOnce call, isolating
// per-checker failures, and pushes the combined batch to the
// Collector, queueing locally if the push fails.
type Runner struct {
	AgentID  string
	Checkers []checker.Checker
	Pusher   *Pusher
	Queue    *Queue
}

// NewRunner returns a Runner for the given agent ID, checkers, pusher,
// and local retry queue.
func NewRunner(agentID string, checkers []checker.Checker, pusher *Pusher, queue *Queue) *Runner {
	return &Runner{AgentID: agentID, Checkers: checkers, Pusher: pusher, Queue: queue}
}

// RunOnce flushes any queued backlog, runs every configured Checker
// once, and pushes the combined results to the Collector. A failing
// Checker never blocks the others; if the push itself fails, the
// batch is queued locally instead of dropped.
func (r *Runner) RunOnce(ctx context.Context) error {
	if err := r.Queue.Drain(ctx, func(b checker.Batch) error { return r.Pusher.Push(ctx, b) }); err != nil {
		log.Printf("agent: queue drain failed, will retry later: %s", logging.Sanitize(err.Error()))
	}

	checkedAt := time.Now().UTC()
	var results []checker.Result
	for _, c := range r.Checkers {
		records, err := c.Check(ctx)
		result := checker.Result{CheckerName: c.Name(), Records: records, CheckedAt: checkedAt}
		if err != nil {
			result.ErrMsg = err.Error()
		}
		results = append(results, result)
	}

	batch := checker.Batch{AgentID: r.AgentID, Results: results}

	if err := r.Pusher.Push(ctx, batch); err != nil {
		log.Printf("agent: push failed, queuing locally: %s", logging.Sanitize(err.Error()))
		if err := r.Queue.Enqueue(batch); err != nil {
			return err
		}
	}

	return nil
}
