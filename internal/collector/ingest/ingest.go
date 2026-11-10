// Package ingest implements the Collector's batch ingestion endpoint.
package ingest

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/store"
	"github.com/Joao-Paulino/expiry-radar/internal/logging"
)

// Handler decodes a pushed checker.Batch and persists its results.
func Handler(st store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		var batch checker.Batch
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			log.Printf("ingest: decode error: %s", logging.Sanitize(err.Error()))
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		for _, result := range batch.Results {
			if result.ErrMsg == "" {
				if err := st.SaveRecords(ctx, batch.AgentID, result.Records); err != nil {
					log.Printf("ingest: SaveRecords error: %s", logging.Sanitize(err.Error()))
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				if err := st.RecordCheckerHealth(ctx, result.CheckerName, batch.AgentID, nil); err != nil {
					log.Printf("ingest: RecordCheckerHealth error: %s", logging.Sanitize(err.Error()))
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				continue
			}
			if err := st.RecordCheckerHealth(ctx, result.CheckerName, batch.AgentID, errors.New(result.ErrMsg)); err != nil {
				log.Printf("ingest: RecordCheckerHealth error: %s", logging.Sanitize(err.Error()))
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
