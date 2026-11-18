package inventory

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCheck_CSV(t *testing.T) {
	p := write(t, "ot-assets.csv", "name,source,kind,expires_at,owner,vendor\n"+
		"Danfoss AK-SM 800 Store 12,10.20.1.15,end_of_support,2025-12-31,ot-team,Danfoss\n"+
		"Siemens S7-1500 Line 3,plc-03.plant,,2027-06-30T00:00:00Z,,\n")
	recs, err := New(Config{Files: []string{p}}).Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d records", len(recs))
	}
	r := recs[0]
	if r.Name != "Danfoss AK-SM 800 Store 12" || r.Source != "10.20.1.15" || r.Kind != "end_of_support" ||
		!r.ExpiresAt.Equal(time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("record = %+v", r)
	}
	if r.Metadata["owner"] != "ot-team" || r.Metadata["vendor"] != "Danfoss" {
		t.Errorf("metadata = %v", r.Metadata)
	}
	if recs[1].Kind != "end_of_support" { // default kind
		t.Errorf("default kind = %q", recs[1].Kind)
	}
	if _, ok := recs[1].Metadata["owner"]; ok {
		t.Errorf("empty columns must not become metadata: %v", recs[1].Metadata)
	}
}

func TestCheck_JSON(t *testing.T) {
	p := write(t, "contracts.json", `[
 {"name": "Firewall support contract", "kind": "support_contract", "expires_at": "2027-03-01", "metadata": {"vendor": "Example"}},
 {"name": "example.com", "source": "registrar", "kind": "domain", "expires_at": "2027-08-15"}]`)
	recs, err := New(Config{Files: []string{p}}).Check(context.Background())
	if err != nil || len(recs) != 2 {
		t.Fatalf("recs=%+v err=%v", recs, err)
	}
	if recs[0].Source != "inventory://contracts.json" { // default source
		t.Errorf("default source = %q", recs[0].Source)
	}
	if recs[0].Metadata["vendor"] != "Example" || recs[1].Kind != "domain" {
		t.Errorf("recs = %+v", recs)
	}
}

// A bad row is reported with its line, and the good rows still count.
func TestCheck_BadRowsAreErrorsButOthersReported(t *testing.T) {
	p := write(t, "a.csv", "name,expires_at\nok,2027-01-01\n,2027-01-01\nbad date,31/12/2027\n")
	recs, err := New(Config{Files: []string{p}}).Check(context.Background())
	if len(recs) != 1 || recs[0].Name != "ok" {
		t.Fatalf("recs = %+v", recs)
	}
	if err == nil || !strings.Contains(err.Error(), "line 3") || !strings.Contains(err.Error(), "line 4") {
		t.Fatalf("err = %v", err)
	}
}

func TestCheck_MissingFileAndColumns(t *testing.T) {
	noCol := write(t, "b.csv", "name,date\nx,2027-01-01\n")
	_, err := New(Config{Files: []string{"/does/not/exist.csv", noCol}}).Check(context.Background())
	if err == nil || !strings.Contains(err.Error(), "exist.csv") || !strings.Contains(err.Error(), "expires_at") {
		t.Fatalf("err = %v", err)
	}
}

func TestConfig_Validate(t *testing.T) {
	if (Config{}).Validate() == nil {
		t.Error("empty files accepted")
	}
	if (Config{Files: []string{"x.txt"}}).Validate() == nil {
		t.Error("unsupported extension accepted")
	}
	if err := (Config{Files: []string{"a.csv", "b.json"}}).Validate(); err != nil {
		t.Error(err)
	}
}

// The documented example must parse cleanly.
func TestCheck_ExampleFile(t *testing.T) {
	recs, err := New(Config{Files: []string{"../../../examples/ot-assets.csv"}}).Check(context.Background())
	if err != nil || len(recs) != 5 {
		t.Fatalf("recs=%d err=%v", len(recs), err)
	}
}
