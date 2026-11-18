// Package inventory implements a Checker for dates kept in files: device
// end of support, firmware support, support contracts, warranties,
// domains, SaaS subscriptions. Anything with an expiry date that no API
// exposes. It only reads the files; it never contacts the devices.
package inventory

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
)

// Limits for hand-edited files.
const (
	maxFileBytes = 10 << 20
	maxRows      = 100000
	maxField     = 1024
	defaultKind  = "end_of_support"
)

// Config lists the inventory files (.csv or .json).
type Config struct {
	Files []string `json:"files"`
}

// Validate checks that at least one .csv or .json file is listed.
func (c Config) Validate() error {
	if len(c.Files) == 0 {
		return errors.New("inventory: at least one file is required")
	}
	for _, f := range c.Files {
		switch strings.ToLower(filepath.Ext(f)) {
		case ".csv", ".json":
		default:
			return fmt.Errorf("inventory: %s: only .csv and .json files are supported", f)
		}
	}
	return nil
}

// Checker reports the entries of inventory files.
type Checker struct{ cfg Config }

// New returns a Checker for cfg.
func New(cfg Config) *Checker { return &Checker{cfg: cfg} }

// Name identifies this checker.
func (c *Checker) Name() string { return "inventory" }

// Kind classifies what this checker produces by default.
func (c *Checker) Kind() string { return defaultKind }

// Check reads every file. A broken row or file is an error, but every
// valid row is still reported.
func (c *Checker) Check(ctx context.Context) ([]checker.ExpiryRecord, error) {
	var out []checker.ExpiryRecord
	var errs []error
	for _, f := range c.cfg.Files {
		if err := ctx.Err(); err != nil {
			return out, errors.Join(append(errs, err)...)
		}
		b, err := readLimited(f)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		var recs []checker.ExpiryRecord
		if strings.EqualFold(filepath.Ext(f), ".json") {
			recs, err = parseJSON(f, b)
		} else {
			recs, err = parseCSV(f, b)
		}
		out = append(out, recs...)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return out, errors.Join(errs...)
}

func readLimited(path string) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- path comes from the admin-owned agent config
	if err != nil {
		return nil, fmt.Errorf("inventory: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("inventory: %s: %w", path, err)
	}
	if len(b) > maxFileBytes {
		return nil, fmt.Errorf("inventory: %s: larger than %d bytes", path, maxFileBytes)
	}
	return bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")), nil // Excel saves CSV with a BOM
}

type entry struct {
	Name      string            `json:"name"`
	Source    string            `json:"source"`
	Kind      string            `json:"kind"`
	ExpiresAt string            `json:"expires_at"`
	Metadata  map[string]string `json:"metadata"`
}

// toRecord validates one entry; file and where locate errors.
func toRecord(file, where string, e entry) (checker.ExpiryRecord, error) {
	name := strings.TrimSpace(e.Name)
	if name == "" {
		return checker.ExpiryRecord{}, fmt.Errorf("inventory: %s %s: name is required", file, where)
	}
	at, err := parseDate(strings.TrimSpace(e.ExpiresAt))
	if err != nil {
		return checker.ExpiryRecord{}, fmt.Errorf("inventory: %s %s: expires_at %q: use YYYY-MM-DD or RFC 3339", file, where, clip(e.ExpiresAt))
	}
	src := strings.TrimSpace(e.Source)
	if src == "" {
		src = "inventory://" + filepath.Base(file)
	}
	kind := strings.TrimSpace(e.Kind)
	if kind == "" {
		kind = defaultKind
	}
	meta := map[string]string{}
	for k, v := range e.Metadata {
		if k = strings.TrimSpace(k); k != "" && strings.TrimSpace(v) != "" {
			meta[clip(k)] = clip(strings.TrimSpace(v))
		}
	}
	return checker.ExpiryRecord{Source: clip(src), Name: clip(name), Kind: clip(kind), ExpiresAt: at, Metadata: meta}, nil
}

func parseDate(s string) (time.Time, error) {
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, s)
}

func clip(s string) string {
	if len(s) > maxField {
		return s[:maxField]
	}
	return s
}

// parseCSV reads a CSV with a header row. name and expires_at are
// required columns; source and kind are optional; any other column
// becomes metadata.
func parseCSV(file string, b []byte) ([]checker.ExpiryRecord, error) {
	r := csv.NewReader(bytes.NewReader(b))
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true
	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("inventory: %s: reading header: %w", file, err)
	}
	col := map[string]int{}
	for i, h := range header {
		col[strings.ToLower(strings.TrimSpace(h))] = i
	}
	for _, need := range []string{"name", "expires_at"} {
		if _, ok := col[need]; !ok {
			return nil, fmt.Errorf("inventory: %s: missing column %q (need name and expires_at)", file, need)
		}
	}
	get := func(row []string, name string) string {
		if i, ok := col[name]; ok && i < len(row) {
			return row[i]
		}
		return ""
	}
	var out []checker.ExpiryRecord
	var errs []error
	for n := 0; ; n++ {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("inventory: %s: %w", file, err))
			break
		}
		line := n + 2
		if len(row) > 0 {
			line, _ = r.FieldPos(0)
		}
		if n >= maxRows {
			errs = append(errs, fmt.Errorf("inventory: %s: more than %d rows", file, maxRows))
			break
		}
		meta := map[string]string{}
		for h, i := range col {
			switch h {
			case "name", "source", "kind", "expires_at":
			default:
				if i < len(row) {
					meta[h] = row[i]
				}
			}
		}
		rec, err := toRecord(file, fmt.Sprintf("line %d", line), entry{
			Name: get(row, "name"), Source: get(row, "source"), Kind: get(row, "kind"),
			ExpiresAt: get(row, "expires_at"), Metadata: meta,
		})
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, rec)
	}
	return out, errors.Join(errs...)
}

// parseJSON reads a JSON array of entries.
func parseJSON(file string, b []byte) ([]checker.ExpiryRecord, error) {
	var entries []entry
	if err := json.Unmarshal(b, &entries); err != nil {
		return nil, fmt.Errorf("inventory: %s: %w", file, err)
	}
	if len(entries) > maxRows {
		return nil, fmt.Errorf("inventory: %s: more than %d entries", file, maxRows)
	}
	var out []checker.ExpiryRecord
	var errs []error
	for i, e := range entries {
		rec, err := toRecord(file, fmt.Sprintf("entry %d", i+1), e)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, rec)
	}
	return out, errors.Join(errs...)
}
