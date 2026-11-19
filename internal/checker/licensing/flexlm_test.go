package licensing

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
)

func writeLicFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "license.dat")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func byName(recs []checker.ExpiryRecord) map[string]checker.ExpiryRecord {
	m := map[string]checker.ExpiryRecord{}
	for _, r := range recs {
		m[r.Name] = r
	}
	return m
}

func TestCheck_FlexLM_FeatureLine(t *testing.T) {
	path := writeLicFile(t, `FEATURE quartus_pro alterad 2021.05 31-Dec-2025 uncounted 46499B9E717E
`)
	recs, err := Checkers(&Config{FlexLMLicenseFiles: []string{path}})[0].Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	m := byName(recs)
	rec, ok := m["quartus_pro"]
	if !ok {
		t.Fatalf("want a record for quartus_pro, got %v", recs)
	}
	if !rec.ExpiresAt.Equal(time.Date(2025, time.December, 31, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("expiry: %v", rec.ExpiresAt)
	}
	if rec.Kind != "license" || rec.Metadata["vendor_daemon"] != "alterad" || rec.Metadata["version"] != "2021.05" {
		t.Fatalf("record: %+v", rec)
	}
}

func TestCheck_FlexLM_PermanentAndZeroSkipped(t *testing.T) {
	path := writeLicFile(t, `FEATURE perm1 vendord 1.0 permanent uncounted ABC123
FEATURE perm2 vendord 1.0 0 uncounted DEF456
`)
	recs, err := Checkers(&Config{FlexLMLicenseFiles: []string{path}})[0].Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 0 {
		t.Fatalf("want no records for permanent/non-expiring licenses: %v", recs)
	}
}

func TestCheck_FlexLM_LowercaseMonthAndSingleDigitDay(t *testing.T) {
	path := writeLicFile(t, `INCREMENT questasim mgcd 2022.06 9-jun-2022 10 AUTH123
`)
	recs, err := Checkers(&Config{FlexLMLicenseFiles: []string{path}})[0].Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	m := byName(recs)
	rec, ok := m["questasim"]
	if !ok {
		t.Fatalf("want a record for questasim, got %v", recs)
	}
	if !rec.ExpiresAt.Equal(time.Date(2022, time.June, 9, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("expiry: %v", rec.ExpiresAt)
	}
}

func TestCheck_FlexLM_ContinuationLineWithSignBlob(t *testing.T) {
	path := writeLicFile(t, "FEATURE quartus_pro alterad 2021.05 15-Mar-2026 uncounted 46499B9E717E \\\n"+
		"HOSTID=e4a4716b48d8 TS_OK SIGN=\"08EF B762 CF6A 18CC FF95 B124 \\\n"+
		"2FB0 F8F0 7A43 CAFE\"\n")
	recs, err := Checkers(&Config{FlexLMLicenseFiles: []string{path}})[0].Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	m := byName(recs)
	rec, ok := m["quartus_pro"]
	if !ok {
		t.Fatalf("want a record for quartus_pro despite the continued SIGN blob: %v", recs)
	}
	if !rec.ExpiresAt.Equal(time.Date(2026, time.March, 15, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("expiry: %v", rec.ExpiresAt)
	}
}

func TestCheck_FlexLM_CommentsAndBlankLinesSkipped(t *testing.T) {
	path := writeLicFile(t, `# this is a comment
SERVER host1 ANY 27000

FEATURE feat1 vd 1.0 01-Jan-2030 1 CODE
`)
	recs, err := Checkers(&Config{FlexLMLicenseFiles: []string{path}})[0].Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Name != "feat1" {
		t.Fatalf("want exactly 1 record (feat1): %v", recs)
	}
}

func TestCheck_FlexLM_MalformedLineIsReportedNotSilentlyDropped(t *testing.T) {
	path := writeLicFile(t, `FEATURE too_short vd 1.0
FEATURE ok_one vd 1.0 01-Jan-2030 1 CODE
`)
	recs, err := Checkers(&Config{FlexLMLicenseFiles: []string{path}})[0].Check(context.Background())
	if err == nil {
		t.Fatal("want an error for the malformed FEATURE line")
	}
	if len(recs) != 1 || recs[0].Name != "ok_one" {
		t.Fatalf("want the well-formed line still processed: %v", recs)
	}
}

func TestCheck_FlexLM_UnreadableFileIsReported(t *testing.T) {
	recs, err := Checkers(&Config{FlexLMLicenseFiles: []string{filepath.Join(t.TempDir(), "missing.lic")}})[0].Check(context.Background())
	if err == nil || len(recs) != 0 {
		t.Fatalf("want an error and no records for a missing file, got recs=%v err=%v", recs, err)
	}
}

func TestConfig_Validate(t *testing.T) {
	c := &Config{FlexLMLicenseFiles: []string{" "}}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "flexlm_license_files") {
		t.Fatalf("want a validation error for a blank path, got %v", err)
	}
}

func TestCheckers_NilConfig(t *testing.T) {
	if cs := Checkers(nil); cs != nil {
		t.Fatalf("want nil checkers for nil config, got %v", cs)
	}
	if cs := Checkers(&Config{}); cs != nil {
		t.Fatalf("want nil checkers when flexlm_license_files is empty, got %v", cs)
	}
}
