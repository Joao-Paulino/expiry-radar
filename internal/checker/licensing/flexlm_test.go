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

// Per Revenera's FlexNet Publisher License Administration Guide, a
// year of 0/00/000/0000 in the expiration field also means
// "never expires" (same as the literal "permanent" keyword) - not
// just a bare "0" with no date shape at all.
// Per the FLEXlm FAQ (Q3.5): "Dates in the 20th century (19xx) can be
// abbreviated to the last 2 digits of the year"; only 2000-and-later
// dates must spell out all 4 digits. So a 2-digit year always means
// 19xx, never 20xx - no pivot, no ambiguity.
func TestCheck_FlexLM_TwoDigitYearIs19xx(t *testing.T) {
	path := writeLicFile(t, `FEATURE legacy_tool vd 1.0 1-jan-95 1 CODE1
`)
	recs, err := Checkers(&Config{FlexLMLicenseFiles: []string{path}})[0].Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	m := byName(recs)
	rec, ok := m["legacy_tool"]
	if !ok {
		t.Fatalf("want a record for legacy_tool, got %v", recs)
	}
	if !rec.ExpiresAt.Equal(time.Date(1995, time.January, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("want a 2-digit year to mean 19xx, got expiry: %v", rec.ExpiresAt)
	}
}

func TestCheck_FlexLM_ZeroYearIsPermanent(t *testing.T) {
	path := writeLicFile(t, `FEATURE f1 vd 1.0 01-jan-0000 1 CODE1
FEATURE f2 vd 1.0 1-jan-00 1 CODE2
`)
	recs, err := Checkers(&Config{FlexLMLicenseFiles: []string{path}})[0].Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 0 {
		t.Fatalf("want no records for zero-year (never expires) licenses: %v", recs)
	}
}

// Real license files routinely carry more than one FEATURE/INCREMENT
// line for the same feature name (a renewal appended next to the old
// grant). Each must get a distinct Source, or the collector's
// (source, name, kind) keying silently collapses them into one -
// and if the stale/expired one sorts first, the renewed one becomes
// invisible forever.
func TestCheck_FlexLM_DuplicateFeatureNameGetsDistinctSources(t *testing.T) {
	path := writeLicFile(t, `FEATURE widget vd 1.0 01-Jan-2020 1 OLD
FEATURE widget vd 2.0 01-Jan-2030 1 NEW
`)
	recs, err := Checkers(&Config{FlexLMLicenseFiles: []string{path}})[0].Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("want 2 records for the 2 widget grants: %v", recs)
	}
	if recs[0].Source == recs[1].Source {
		t.Fatalf("want distinct Source for each grant, got the same for both: %q", recs[0].Source)
	}
}

// A comment or SERVER/VENDOR line that happens to end in a literal
// backslash (e.g. a Windows path in a comment) must not be treated as
// a FlexLM line-continuation marker - only FEATURE/INCREMENT entries
// legitimately continue across lines.
func TestCheck_FlexLM_BackslashInCommentIsNotAContinuation(t *testing.T) {
	path := writeLicFile(t, "# see C:\\vendor\\notes\\\n"+
		"FEATURE f1 vd 1.0 01-Jan-2030 1 CODE1\n")
	recs, err := Checkers(&Config{FlexLMLicenseFiles: []string{path}})[0].Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Name != "f1" {
		t.Fatalf("want the FEATURE line after the comment still parsed: %v", recs)
	}
}

// Windows editors and PowerShell's Out-File often prepend a UTF-8 BOM
// (the agent's own JSON config loader already strips one for the same
// reason); a FlexLM file with one must not lose its first entry.
func TestCheck_FlexLM_UTF8BOMStripped(t *testing.T) {
	path := writeLicFile(t, "\xef\xbb\xbfFEATURE f1 vd 1.0 01-Jan-2030 1 CODE1\n")
	recs, err := Checkers(&Config{FlexLMLicenseFiles: []string{path}})[0].Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Name != "f1" {
		t.Fatalf("want the BOM-prefixed FEATURE line parsed: %v", recs)
	}
}

// fakeCtx's Err() starts nil and turns non-nil after a fixed number
// of calls, simulating a context cancelled partway through a
// multi-file run without any real concurrency/timing.
type fakeCtx struct {
	context.Context
	callsUntilDone int
	calls          int
}

func (f *fakeCtx) Err() error {
	f.calls++
	if f.calls > f.callsUntilDone {
		return context.Canceled
	}
	return nil
}

// If the context is cancelled partway through a multi-file run,
// errors already collected from earlier files must not be discarded
// in favor of a bare ctx.Err().
func TestCheck_FlexLM_ContextCancelledKeepsPriorErrors(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.lic")
	ok := writeLicFile(t, "FEATURE f1 vd 1.0 01-Jan-2030 1 CODE1\n")
	ctx := &fakeCtx{Context: context.Background(), callsUntilDone: 1} // nil on path 1's check, cancelled before path 2
	recs, err := Checkers(&Config{FlexLMLicenseFiles: []string{missing, ok}})[0].Check(ctx)
	if err == nil || !strings.Contains(err.Error(), "missing.lic") {
		t.Fatalf("want the first file's error preserved alongside the cancellation, got recs=%v err=%v", recs, err)
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
