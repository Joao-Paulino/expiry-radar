// Package licensing checks third-party software license files for
// their expiration date. It only reads files the operator already
// configured; it never talks to a license server over the network.
package licensing

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
)

// maxFileBytes caps how large a FlexLM license file we'll read, in
// line with the inventory checker's cap for hand-edited operator
// files (internal/checker/inventory).
const maxFileBytes = 10 << 20

// Config is the "licensing" section of the agent configuration.
type Config struct {
	// FlexLMLicenseFiles are FlexLM/FlexNet license files (.lic/.dat)
	// to read for FEATURE/INCREMENT expiration dates. Local files
	// only: querying a running license server (lmgrd/lmstat) is not
	// supported.
	FlexLMLicenseFiles []string `json:"flexlm_license_files"`
}

// Validate checks the configuration.
func (c *Config) Validate() error {
	if c == nil {
		return nil
	}
	for _, p := range c.FlexLMLicenseFiles {
		if strings.TrimSpace(p) == "" {
			return errors.New("licensing: flexlm_license_files must not contain empty entries")
		}
	}
	return nil
}

// Checkers returns the checkers the configuration enables.
func Checkers(c *Config) []checker.Checker {
	if c == nil || len(c.FlexLMLicenseFiles) == 0 {
		return nil
	}
	return []checker.Checker{&flexlmChecker{paths: c.FlexLMLicenseFiles}}
}

type flexlmChecker struct{ paths []string }

// Name is the checker name reported to the collector.
func (f *flexlmChecker) Name() string { return "flexlm" }

// Kind is the record kind this checker produces.
func (f *flexlmChecker) Kind() string { return "license" }

// Check parses every configured FlexLM license file. An unreadable
// file or a malformed FEATURE/INCREMENT line is an error (the run is
// incomplete); other lines (SERVER, VENDOR, comments) are skipped.
func (f *flexlmChecker) Check(ctx context.Context) ([]checker.ExpiryRecord, error) {
	var recs []checker.ExpiryRecord
	var errs []error
	for _, path := range f.paths {
		if ctx.Err() != nil {
			errs = append(errs, ctx.Err())
			break
		}
		fr, err := parseFlexLMFile(path)
		if err != nil {
			errs = append(errs, err)
		}
		recs = append(recs, fr...)
	}
	return recs, errors.Join(errs...)
}

// flexlmFeature is one FEATURE/INCREMENT entry.
type flexlmFeature struct {
	name, vendor, version, count string
	expiry                       time.Time
	permanent                    bool
}

func parseFlexLMFile(path string) ([]checker.ExpiryRecord, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path comes from the operator's own configuration, not from remote input
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(data) > maxFileBytes {
		return nil, fmt.Errorf("%s: file is %d bytes, exceeds the %d byte limit for a license file", path, len(data), maxFileBytes)
	}
	// Editors and PowerShell's Out-File often prepend a UTF-8 BOM.
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))

	var recs []checker.ExpiryRecord
	var errs []error
	seen := map[string]int{} // occurrence count per feature name, for a unique Source when a name repeats
	for _, line := range joinFlexLMContinuations(string(data)) {
		f, ok, err := parseFeatureLine(line)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, err))
			continue
		}
		if !ok || f.permanent {
			continue
		}
		source := "flexlm://" + path + "/" + f.name
		if n := seen[f.name]; n > 0 {
			source += "#" + strconv.Itoa(n+1)
		}
		seen[f.name]++
		recs = append(recs, checker.ExpiryRecord{
			Source: source, Name: f.name, Kind: "license",
			ExpiresAt: f.expiry,
			Metadata:  map[string]string{"vendor_daemon": f.vendor, "version": f.version, "count": f.count},
		})
	}
	return recs, errors.Join(errs...)
}

// joinFlexLMContinuations folds lines ending in "\" into the next
// physical line (FlexLM's SIGN= blobs commonly span several lines),
// then returns the logical lines.
func joinFlexLMContinuations(data string) []string {
	var lines []string
	var cur strings.Builder
	for _, raw := range strings.Split(data, "\n") {
		raw = strings.TrimRight(raw, "\r")
		// A comment line (outside of an already-started continuation)
		// is never a continuation marker, even if it ends in "\" (e.g.
		// a Windows path mentioned in the comment).
		if cur.Len() == 0 && strings.HasPrefix(strings.TrimSpace(raw), "#") {
			lines = append(lines, raw)
			continue
		}
		if strings.HasSuffix(raw, "\\") {
			cur.WriteString(strings.TrimSuffix(raw, "\\"))
			cur.WriteByte(' ')
			continue
		}
		cur.WriteString(raw)
		lines = append(lines, cur.String())
		cur.Reset()
	}
	if cur.Len() > 0 {
		lines = append(lines, cur.String())
	}
	return lines
}

// parseFeatureLine extracts a FEATURE/INCREMENT entry from one
// logical line. ok is false for a line that is not a FEATURE or
// INCREMENT entry (blank, a comment, SERVER/VENDOR/USE_SERVER, ...).
func parseFeatureLine(line string) (flexlmFeature, bool, error) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return flexlmFeature{}, false, nil
	}
	tag := fields[0]
	if tag != "FEATURE" && tag != "INCREMENT" {
		return flexlmFeature{}, false, nil
	}
	// FEATURE/INCREMENT <name> <vendor-daemon> <version> <expiration> <count> ...
	if len(fields) < 6 {
		return flexlmFeature{}, false, fmt.Errorf("malformed %s line (want at least 6 fields): %q", tag, line)
	}
	f := flexlmFeature{name: fields[1], vendor: fields[2], version: fields[3], count: fields[5]}
	exp := fields[4]
	if strings.EqualFold(exp, "permanent") || isZeroYearExpiration(exp) {
		f.permanent = true
		return f, true, nil
	}
	t, err := parseFlexLMDate(exp)
	if err != nil {
		return flexlmFeature{}, false, fmt.Errorf("feature %s: %w", f.name, err)
	}
	f.expiry = t
	return f, true, nil
}

// isZeroYearExpiration reports whether exp is a FlexLM non-expiring
// date: the literal "0", or a D-mon-YYYY date whose year component is
// all zeros (0, 00, 000, or 0000) - all documented non-expiring forms
// per Revenera's FlexNet Publisher License Administration Guide.
func isZeroYearExpiration(exp string) bool {
	if exp == "0" {
		return true
	}
	parts := strings.SplitN(exp, "-", 3)
	if len(parts) != 3 || parts[2] == "" {
		return false
	}
	for _, r := range parts[2] {
		if r != '0' {
			return false
		}
	}
	return true
}

// parseFlexLMDate parses a FlexLM expiration date: D-mon-YYYY, with a
// one- or two-digit day and a case-insensitive three-letter month
// (e.g. "31-Dec-2025" or "9-jun-2022").
func parseFlexLMDate(s string) (time.Time, error) {
	parts := strings.SplitN(s, "-", 3)
	if len(parts) != 3 || len(parts[1]) == 0 {
		return time.Time{}, fmt.Errorf("unrecognized expiration date %q (want D-mon-YYYY)", s)
	}
	month := strings.ToUpper(parts[1][:1]) + strings.ToLower(parts[1][1:])
	t, err := time.Parse("2-Jan-2006", parts[0]+"-"+month+"-"+parts[2])
	if err != nil {
		return time.Time{}, fmt.Errorf("unrecognized expiration date %q (want D-mon-YYYY): %w", s, err)
	}
	return t, nil
}
