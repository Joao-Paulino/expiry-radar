// Package local reports the certificates already installed on the
// machine the agent runs on: PEM/DER files under configured paths and,
// on Windows, the LocalMachine certificate stores (IIS, RDP, Exchange
// keep theirs in "My" and "WebHosting"). Read only; private keys are
// never opened.
package local

import (
	"context"
	"crypto/sha1" // #nosec G505 -- thumbprint identifier only (Windows convention), not a security control
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
)

// Config is the "local" section of the agent configuration.
type Config struct {
	// CertPaths are files or directories (searched recursively) holding
	// certificates: .pem .crt .cer .der. Other files are ignored.
	CertPaths []string `json:"cert_paths"`
	// WindowsCertStores are LocalMachine stores to read on Windows,
	// e.g. ["My", "WebHosting"] (the default when the list is nil).
	// Set to [] to read none.
	WindowsCertStores []string `json:"windows_cert_stores"`
}

var certExts = map[string]bool{".pem": true, ".crt": true, ".cer": true, ".der": true}

// Validate checks the configuration.
func (c *Config) Validate() error {
	if c == nil {
		return nil
	}
	for _, p := range c.CertPaths {
		if strings.TrimSpace(p) == "" {
			return errors.New("local: cert_paths must not contain empty entries")
		}
	}
	for _, s := range c.WindowsCertStores {
		if strings.ContainsAny(s, `\/`) || s == "" {
			return fmt.Errorf("local: windows_cert_stores entry %q must be a store name such as My or WebHosting", s)
		}
	}
	return nil
}

// Checkers returns the checkers the configuration enables: file paths
// as "local-certs", and on Windows the certificate stores as
// "windows-certstore". Kept separate so an unreadable file does not
// mark the store results incomplete, and vice versa.
func Checkers(c *Config) []checker.Checker {
	if c == nil {
		return nil
	}
	var out []checker.Checker
	if len(c.CertPaths) > 0 {
		out = append(out, &fileChecker{paths: c.CertPaths})
	}
	if runtime.GOOS == "windows" {
		stores := c.WindowsCertStores
		if stores == nil {
			stores = []string{"My", "WebHosting"}
		}
		if len(stores) > 0 {
			out = append(out, &storeChecker{stores: stores})
		}
	}
	return out
}

type fileChecker struct{ paths []string }

// Name is the checker name reported to the collector.
func (f *fileChecker) Name() string { return "local-certs" }

// Kind is the record kind this checker produces.
func (f *fileChecker) Kind() string { return "certificate" }

// Check parses every certificate file under the configured paths. A
// path that cannot be read or a certificate file that cannot be parsed
// is an error (the run is incomplete); files without a certificate are
// skipped.
func (f *fileChecker) Check(ctx context.Context) ([]checker.ExpiryRecord, error) {
	var recs []checker.ExpiryRecord
	var errs []error
	for _, root := range f.paths {
		info, err := os.Stat(root)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		visit := func(path string) {
			certs, err := readCertFile(path)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", path, err))
				return
			}
			recs = append(recs, records("file://"+filepath.ToSlash(path), certs)...)
		}
		if !info.IsDir() {
			visit(root)
			continue
		}
		err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				errs = append(errs, err)
				return nil
			}
			if !d.IsDir() && certExts[strings.ToLower(filepath.Ext(path))] {
				visit(path)
			}
			return nil
		})
		if err != nil {
			return recs, err
		}
	}
	return recs, errors.Join(errs...)
}

// readCertFile returns the certificates in a PEM or DER file, or none
// when the file holds something else (a key, a CSR).
func readCertFile(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path comes from the operator's own configuration, not from remote input
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	rest := data
	sawPEM := false
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		sawPEM = true
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate: %w", err)
		}
		certs = append(certs, c)
	}
	if sawPEM {
		return certs, nil
	}
	c, err := x509.ParseCertificate(data)
	if err != nil {
		// A .pem without certificates (a key, a CSR) is normal; a
		// .crt/.cer/.der that is not DER is a broken file.
		if strings.EqualFold(filepath.Ext(path), ".pem") {
			return nil, nil
		}
		return nil, fmt.Errorf("not a PEM or DER certificate: %w", err)
	}
	return []*x509.Certificate{c}, nil
}

// records builds one record per certificate. Names repeat (the same CN
// in a chain, or several certificates for one site), so a short
// thumbprint is appended whenever a name occurs twice under a source.
func records(source string, certs []*x509.Certificate) []checker.ExpiryRecord {
	byName := map[string]int{}
	for _, c := range certs {
		byName[displayName(c)]++
	}
	var out []checker.ExpiryRecord
	for _, c := range certs {
		sum := sha1.Sum(c.Raw) // #nosec G401 -- thumbprint identifier, as shown by Windows and browsers
		thumb := hex.EncodeToString(sum[:])
		name := displayName(c)
		if byName[name] > 1 {
			name += " · " + thumb[len(thumb)-8:]
		}
		md := map[string]string{
			"issuer":     c.Issuer.CommonName,
			"thumbprint": thumb,
			"serial":     c.SerialNumber.Text(16),
		}
		if c.IsCA {
			md["ca"] = "true"
		}
		if len(c.DNSNames) > 0 {
			names := append([]string(nil), c.DNSNames...)
			sort.Strings(names)
			md["sans"] = strings.Join(names, ",")
		}
		out = append(out, checker.ExpiryRecord{Source: source, Name: name, Kind: "certificate", ExpiresAt: c.NotAfter, Metadata: md})
	}
	return out
}

func displayName(c *x509.Certificate) string {
	switch {
	case c.Subject.CommonName != "":
		return c.Subject.CommonName
	case len(c.DNSNames) > 0:
		return c.DNSNames[0]
	default:
		return "serial " + c.SerialNumber.Text(16)
	}
}
