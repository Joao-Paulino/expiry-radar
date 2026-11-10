package export

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"testing"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/store"
)

func TestJSON_WritesValidArray(t *testing.T) {
	var buf bytes.Buffer
	recs := []store.StoredRecord{{ExpiryRecord: checker.ExpiryRecord{Source: "a", Name: "b", Kind: "certificate", ExpiresAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}}}
	if err := JSON(&buf, recs); err != nil {
		t.Fatal(err)
	}
	var decoded []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if decoded[0]["source"] != "a" {
		t.Fatalf("got %+v", decoded[0])
	}
}

func TestCSV_WritesHeaderAndRow(t *testing.T) {
	var buf bytes.Buffer
	recs := []store.StoredRecord{{ExpiryRecord: checker.ExpiryRecord{Source: "a", Name: "b", Kind: "certificate", ExpiresAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}}}
	if err := CSV(&buf, recs); err != nil {
		t.Fatal(err)
	}
	reader := csv.NewReader(&buf)
	rows, err := reader.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 { // header + 1 data row
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	if rows[0][0] != "source" {
		t.Fatalf("header = %v", rows[0])
	}
}
