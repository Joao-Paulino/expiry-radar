// Package opcua implements a Checker for OPC UA server certificates.
//
// It asks each server for its endpoints (GetEndpoints) over an unsecured
// secure channel, the discovery path every OPC UA server offers, and
// reports the application instance certificate found in them. It never
// creates a session and never reads or writes node values, so it is safe
// to point at production ICS/OT servers.
package opcua

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
)

// Target is one OPC UA server.
type Target struct {
	// Endpoint is the discovery URL, e.g. opc.tcp://plc-01:4840.
	Endpoint string `json:"endpoint"`
}

// Config configures the OPC UA checker.
type Config struct {
	Targets []Target `json:"targets"`
	// TimeoutSeconds bounds each server (default 10).
	TimeoutSeconds int `json:"timeout_seconds"`
	// PauseSeconds waits between servers so fragile devices are not
	// hit back to back (default 0).
	PauseSeconds int `json:"pause_seconds"`
}

// Validate checks that every target is an opc.tcp:// URL with a host.
func (c Config) Validate() error {
	if len(c.Targets) == 0 {
		return errors.New("opcua: at least one target is required")
	}
	for _, t := range c.Targets {
		u, err := url.Parse(t.Endpoint)
		if err != nil || u.Scheme != "opc.tcp" || u.Hostname() == "" {
			return fmt.Errorf("opcua: invalid endpoint %q (want opc.tcp://host:port)", t.Endpoint)
		}
	}
	if c.TimeoutSeconds < 0 || c.PauseSeconds < 0 {
		return errors.New("opcua: timeout_seconds and pause_seconds must not be negative")
	}
	return nil
}

// Checker reports OPC UA server certificates.
type Checker struct{ cfg Config }

// New returns a Checker for cfg.
func New(cfg Config) *Checker { return &Checker{cfg: cfg} }

// Name identifies this checker.
func (c *Checker) Name() string { return "opcua" }

// Kind classifies what this checker produces.
func (c *Checker) Kind() string { return "certificate" }

// Check queries every target, one at a time, and returns one record per
// distinct certificate. A failure on one target never stops the others.
func (c *Checker) Check(ctx context.Context) ([]checker.ExpiryRecord, error) {
	timeout := time.Duration(c.cfg.TimeoutSeconds) * time.Second
	pause := time.Duration(c.cfg.PauseSeconds) * time.Second
	var records []checker.ExpiryRecord
	var errs []error
	for i, t := range c.cfg.Targets {
		if i > 0 && pause > 0 {
			select {
			case <-ctx.Done():
				return records, errors.Join(append(errs, ctx.Err())...)
			case <-time.After(pause):
			}
		}
		eps, err := GetEndpoints(ctx, t.Endpoint, timeout)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", t.Endpoint, err))
			continue
		}
		recs, err := recordsFor(t.Endpoint, eps)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", t.Endpoint, err))
		}
		records = append(records, recs...)
	}
	return records, errors.Join(errs...)
}

// recordsFor turns endpoints into one record per distinct certificate.
// Servers usually present the same certificate on every secured endpoint.
func recordsFor(source string, eps []Endpoint) ([]checker.ExpiryRecord, error) {
	type seen struct {
		cert     leafInfo
		ep       Endpoint
		policies map[string]bool
	}
	byThumb := map[string]*seen{}
	var order []string
	var errs []error
	for _, ep := range eps {
		if len(ep.ServerCertificate) == 0 {
			continue
		}
		// The field may hold a chain: the leaf comes first.
		leaf, err := parseLeaf(ep.ServerCertificate)
		if err != nil {
			errs = append(errs, fmt.Errorf("endpoint %s: unreadable server certificate", clip(ep.SecurityPolicyURI)))
			continue
		}
		sum := sha256.Sum256(leaf.raw)
		th := hex.EncodeToString(sum[:])
		s, ok := byThumb[th]
		if !ok {
			s = &seen{cert: leaf, ep: ep, policies: map[string]bool{}}
			byThumb[th] = s
			order = append(order, th)
		}
		if p := ep.SecurityPolicyURI; p != "" {
			s.policies[clip(p[strings.LastIndex(p, "#")+1:])] = true
		}
	}
	var out []checker.ExpiryRecord
	for _, th := range order {
		s := byThumb[th]
		policies := make([]string, 0, len(s.policies))
		for p := range s.policies {
			policies = append(policies, p)
		}
		sort.Strings(policies)
		name := s.cert.commonName
		if name == "" {
			name = s.ep.ApplicationName
		}
		if name == "" {
			name = s.ep.ApplicationURI
		}
		meta := map[string]string{
			"issuer":            clip(s.cert.issuerCN),
			"serial":            s.cert.serial,
			"sha256":            th,
			"application_uri":   clip(s.ep.ApplicationURI),
			"security_policies": clip(strings.Join(policies, ",")),
		}
		if s.cert.selfSigned {
			meta["self_signed"] = "true"
		}
		out = append(out, checker.ExpiryRecord{
			Source:    source,
			Name:      clip(name),
			Kind:      "certificate",
			ExpiresAt: s.cert.notAfter,
			Metadata:  meta,
		})
	}
	if len(out) == 0 && len(errs) == 0 {
		errs = append(errs, errors.New("no server certificate advertised on any endpoint"))
	}
	return out, errors.Join(errs...)
}
