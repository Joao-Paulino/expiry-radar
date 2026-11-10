// Package tls implements a Checker that generalizes
// check-cert-renewal.sh's STARTTLS-served-cert logic to an arbitrary
// list of hosts/services.
package tls

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
)

// Target identifies one host/port to check, optionally behind a
// STARTTLS handshake.
type Target struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	// StartTLS names the protocol to speak before the TLS handshake
	// (currently only "smtp"), or "" for a direct TLS connection.
	StartTLS string `json:"start_tls"`
}

// Checker checks TLS certificate expiry for a configured list of targets.
type Checker struct {
	Targets []Target
	// TLSConfig overrides the TLS dial config. Tests use it to set
	// InsecureSkipVerify against a self-signed test server; production
	// code leaves it nil (default verification).
	TLSConfig *tls.Config
}

// New returns a Checker for the given targets.
func New(targets []Target) *Checker {
	return &Checker{Targets: targets}
}

// Name identifies this checker.
func (c *Checker) Name() string { return "tls-checker" }

// Kind classifies what this checker produces.
func (c *Checker) Kind() string { return "certificate" }

// Check connects to every configured target and returns one
// ExpiryRecord per target whose certificate it could read. A failure
// on one target never prevents the others from being checked; any
// failures are joined into the returned error.
func (c *Checker) Check(ctx context.Context) ([]checker.ExpiryRecord, error) {
	var records []checker.ExpiryRecord
	var errs []error

	for _, target := range c.Targets {
		rec, err := c.checkTarget(ctx, target)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s:%d: %w", target.Host, target.Port, err))
			continue
		}
		records = append(records, rec)
	}

	return records, errors.Join(errs...)
}

func (c *Checker) checkTarget(ctx context.Context, target Target) (checker.ExpiryRecord, error) {
	addr := fmt.Sprintf("%s:%d", target.Host, target.Port)

	var tlsConn *tls.Conn
	switch target.StartTLS {
	case "":
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, c.TLSConfig)
		if err != nil {
			return checker.ExpiryRecord{}, err
		}
		tlsConn = conn
	case "smtp":
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		rawConn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return checker.ExpiryRecord{}, err
		}
		client, err := smtp.NewClient(rawConn, target.Host)
		if err != nil {
			rawConn.Close()
			return checker.ExpiryRecord{}, err
		}
		if err := client.StartTLS(c.TLSConfig); err != nil {
			client.Close()
			return checker.ExpiryRecord{}, err
		}
		state, ok := client.TLSConnectionState()
		if !ok {
			client.Close()
			return checker.ExpiryRecord{}, fmt.Errorf("no TLS connection state after STARTTLS")
		}
		if len(state.PeerCertificates) == 0 {
			client.Close()
			return checker.ExpiryRecord{}, fmt.Errorf("no peer certificates presented")
		}
		cert := state.PeerCertificates[0]
		client.Close()
		return checker.ExpiryRecord{
			Source:    addr,
			Name:      cert.Subject.CommonName,
			Kind:      "certificate",
			ExpiresAt: cert.NotAfter,
			Metadata: map[string]string{
				"issuer": cert.Issuer.CommonName,
				"serial": cert.SerialNumber.String(),
			},
		}, nil
	default:
		return checker.ExpiryRecord{}, fmt.Errorf("unsupported StartTLS protocol %q", target.StartTLS)
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return checker.ExpiryRecord{}, fmt.Errorf("no peer certificates presented")
	}
	cert := state.PeerCertificates[0]

	return checker.ExpiryRecord{
		Source:    addr,
		Name:      cert.Subject.CommonName,
		Kind:      "certificate",
		ExpiresAt: cert.NotAfter,
		Metadata: map[string]string{
			"issuer": cert.Issuer.CommonName,
			"serial": cert.SerialNumber.String(),
		},
	}, nil
}
