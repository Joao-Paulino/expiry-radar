// Package ingest implements the Collector's batch ingestion endpoint.
package ingest

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/auth"
	"github.com/Joao-Paulino/expiry-radar/internal/checker"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/store"
	"github.com/Joao-Paulino/expiry-radar/internal/logging"
)

// MaxBodyBytes caps one pushed batch. A large estate is a few thousand
// records of a few hundred bytes each, so 16 MiB leaves ample headroom
// while stopping a faulty or hostile agent from exhausting memory.
const MaxBodyBytes = 16 << 20

// Handler decodes a pushed checker.Batch and persists its results.
func Handler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		var batch checker.Batch
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxBodyBytes)).Decode(&batch); err != nil {
			log.Printf("ingest: decode error: %s", logging.Sanitize(err.Error()))
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// A token bound to an agent may only report as that agent:
		// otherwise one compromised host could retire every other
		// agent's items with empty complete runs.
		if bound, ok := auth.BoundAgent(ctx); ok {
			switch batch.AgentID {
			case "":
				batch.AgentID = bound
			case bound:
			default:
				log.Printf("ingest: token bound to agent %q tried to report as %q (from %s)",
					logging.Sanitize(bound), logging.Sanitize(batch.AgentID), logging.Sanitize(r.RemoteAddr))
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}

		if batch.AgentID != "" {
			if err := st.TouchAgent(ctx, batch.AgentID); err != nil {
				log.Printf("ingest: TouchAgent error: %s", logging.Sanitize(err.Error()))
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}

		for _, result := range batch.Results {
			checkedAt := result.CheckedAt
			if checkedAt.IsZero() {
				// Older/malformed clients that don't set
				// CheckedAt: fall back to receive time rather
				// than storing a zero timestamp.
				checkedAt = time.Now().UTC()
			}
			// An agent clock far ahead would mark runs in the future and
			// hide new items until then: never beyond now + 5 min.
			if limit := time.Now().UTC().Add(5 * time.Minute); checkedAt.After(limit) {
				checkedAt = limit
			}
			// Saved even with no records: an error-free run with nothing
			// in it means every item of this checker is gone.
			if err := st.SaveResult(ctx, batch.AgentID, result.CheckerName, result.Records, checkedAt, result.ErrMsg == ""); err != nil {
				log.Printf("ingest: SaveResult error: %s", logging.Sanitize(err.Error()))
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			var checkErr error
			if result.ErrMsg != "" {
				checkErr = errors.New(result.ErrMsg)
			}
			if err := st.RecordCheckerHealth(ctx, result.CheckerName, batch.AgentID, checkErr); err != nil {
				log.Printf("ingest: RecordCheckerHealth error: %s", logging.Sanitize(err.Error()))
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
