// Package tls implements a Checker that generalizes
// check-cert-renewal.sh's STARTTLS-served-cert logic to an arbitrary
// list of hosts/services.
package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

// dialConfig returns the TLS config used to establish the connection
// itself. It always sets InsecureSkipVerify so that an expired,
// self-signed, or otherwise untrusted certificate never prevents the
// connection (and therefore the expiry record) from being obtained;
// verifyError performs the real verification afterward and the result
// is reported via metadata instead of as a Check failure. ServerName
// is set explicitly because some targets (SMTP STARTTLS in
// particular) are addressed by bare host/IP and the tls/smtp packages
// require ServerName or InsecureSkipVerify to be set — relying only on
// InsecureSkipVerify here keeps SNI correct for virtual-hosted
// targets.
func (c *Checker) dialConfig(host string) *tls.Config {
	cfg := &tls.Config{InsecureSkipVerify: true, ServerName: host}
	if c.TLSConfig != nil && c.TLSConfig.RootCAs != nil {
		cfg.RootCAs = c.TLSConfig.RootCAs
	}
	return cfg
}

// verifyError runs real chain verification against leaf (using any
// remaining peerCerts as intermediates) and returns a non-empty
// string describing the failure, or "" if the certificate verifies
// against roots (nil roots means the system trust store).
func verifyError(leaf *x509.Certificate, peerCerts []*x509.Certificate, roots *x509.CertPool, serverName string) string {
	opts := x509.VerifyOptions{DNSName: serverName, Roots: roots, Intermediates: x509.NewCertPool()}
	for _, ic := range peerCerts[1:] {
		opts.Intermediates.AddCert(ic)
	}
	if _, err := leaf.Verify(opts); err != nil {
		return err.Error()
	}
	return ""
}

func (c *Checker) recordFor(addr string, peerCerts []*x509.Certificate, serverName string) (checker.ExpiryRecord, error) {
	if len(peerCerts) == 0 {
		return checker.ExpiryRecord{}, fmt.Errorf("no peer certificates presented")
	}
	cert := peerCerts[0]

	metadata := map[string]string{
		"issuer": cert.Issuer.CommonName,
		"serial": cert.SerialNumber.String(),
	}
	var roots *x509.CertPool
	if c.TLSConfig != nil {
		roots = c.TLSConfig.RootCAs
	}
	if msg := verifyError(cert, peerCerts, roots, serverName); msg != "" {
		metadata["verify_error"] = msg
	}

	return checker.ExpiryRecord{
		Source:    addr,
		Name:      cert.Subject.CommonName,
		Kind:      "certificate",
		ExpiresAt: cert.NotAfter,
		Metadata:  metadata,
	}, nil
}

func (c *Checker) checkTarget(ctx context.Context, target Target) (checker.ExpiryRecord, error) {
	addr := fmt.Sprintf("%s:%d", target.Host, target.Port)

	switch target.StartTLS {
	case "":
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, c.dialConfig(target.Host))
		if err != nil {
			return checker.ExpiryRecord{}, err
		}
		defer conn.Close()
		return c.recordFor(addr, conn.ConnectionState().PeerCertificates, target.Host)
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
		defer client.Close()
		if err := client.StartTLS(c.dialConfig(target.Host)); err != nil {
			return checker.ExpiryRecord{}, err
		}
		state, ok := client.TLSConnectionState()
		if !ok {
			return checker.ExpiryRecord{}, fmt.Errorf("no TLS connection state after STARTTLS")
		}
		return c.recordFor(addr, state.PeerCertificates, target.Host)
	default:
		return checker.ExpiryRecord{}, fmt.Errorf("unsupported StartTLS protocol %q", target.StartTLS)
	}
}
