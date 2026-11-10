package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"os"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
)

// Queue is a local, file-backed JSONL queue of batches that could not
// be pushed to the Collector, retried on the next Drain.
type Queue struct {
	path string
}

// NewQueue returns a Queue backed by the file at path.
func NewQueue(path string) *Queue {
	return &Queue{path: path}
}

// Enqueue appends b to the queue file as one JSON line.
func (q *Queue) Enqueue(b checker.Batch) error {
	f, err := os.OpenFile(q.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	line, err := json.Marshal(b)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	return nil
}

// Drain reads every queued batch in order and calls send for each. On
// the first error, it stops immediately, rewrites the queue file with
// only the un-sent remaining batches (including the one that just
// failed), and returns that error. On full success, the queue file is
// removed.
func (q *Queue) Drain(ctx context.Context, send func(checker.Batch) error) error {
	batches, err := q.readAll()
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for i, b := range batches {
		if sendErr := send(b); sendErr != nil {
			if writeErr := q.writeAll(batches[i:]); writeErr != nil {
				return writeErr
			}
			return sendErr
		}
	}

	return os.Remove(q.path)
}

func (q *Queue) readAll() ([]checker.Batch, error) {
	f, err := os.Open(q.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var batches []checker.Batch
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var b checker.Batch
		if err := json.Unmarshal(line, &b); err != nil {
			return nil, err
		}
		batches = append(batches, b)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return batches, nil
}

func (q *Queue) writeAll(batches []checker.Batch) error {
	f, err := os.OpenFile(q.path, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, b := range batches {
		line, err := json.Marshal(b)
		if err != nil {
			return err
		}
		if _, err := f.Write(append(line, '\n')); err != nil {
			return err
		}
	}
	return nil
}
