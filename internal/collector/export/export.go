// Package export writes StoredRecords as JSON or CSV.
package export

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/collector/store"
)

// JSON writes records to w as a JSON array.
func JSON(w io.Writer, records []store.StoredRecord) error {
	return json.NewEncoder(w).Encode(records)
}

// CSV writes records to w as CSV, with a header row.
func CSV(w io.Writer, records []store.StoredRecord) error {
	writer := csv.NewWriter(w)
	if err := writer.Write([]string{"source", "name", "kind", "expires_at", "reported_by", "checked_at"}); err != nil {
		return err
	}
	for _, r := range records {
		if err := writer.Write([]string{
			r.Source,
			r.Name,
			r.Kind,
			r.ExpiresAt.Format(time.RFC3339),
			r.ReportedBy,
			r.CheckedAt.Format(time.RFC3339),
		}); err != nil {
			return err
		}
	}
	writer.Flush()
	return writer.Error()
}
