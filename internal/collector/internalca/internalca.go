// Package internalca creates and uses a small internal certificate
// authority for the collector, as a fallback for installations with
// no public domain name (so no Let's Encrypt DNS-01 challenge is
// possible). Unlike a bare self-signed leaf certificate, a CA lets
// the installer issue more certificates later (a new hostname, a
// second collector) without creating a new CA and re-copying trust
// to every agent each time.
package internalca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	caCertFile = "ca.crt"
	caKeyFile  = "ca.key"
	// caValidity is long relative to leaf certificates (365 days by
	// default): the CA is meant to be created once and reused for
	// years, unlike the certificates it issues.
	caValidity = 10 * 365 * 24 * time.Hour
)

// CA is an internal root certificate authority: a self-signed
// certificate and its private key, able to issue leaf certificates
// for the collector.
type CA struct {
	Cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// New creates a new root CA in dir (writing ca.crt and ca.key) and
// returns it. It refuses to overwrite an existing CA in dir: use Load
// or EnsureCA instead.
func New(dir string) (*CA, error) {
	certPath, keyPath := filepath.Join(dir, caCertFile), filepath.Join(dir, caKeyFile)
	for _, p := range []string{certPath, keyPath} {
		if _, err := os.Stat(p); err == nil {
			return nil, fmt.Errorf("internalca: %s already exists; use the existing CA instead of creating a new one", p)
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          new(big.Int).SetInt64(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "Expiry Radar internal CA"},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	if err := writeFileExcl(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return nil, err
	}
	if err := writeFileExcl(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		_ = os.Remove(keyPath) // never leave a key without its certificate
		return nil, err
	}

	return &CA{Cert: cert, key: key}, nil
}

// Load reads an existing CA from dir (ca.crt and ca.key), written
// earlier by New.
func Load(dir string) (*CA, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, caCertFile)) // #nosec G304 -- operator-chosen CA directory
	if err != nil {
		return nil, fmt.Errorf("internalca: read CA certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, caKeyFile)) // #nosec G304 -- operator-chosen CA directory
	if err != nil {
		return nil, fmt.Errorf("internalca: read CA key: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("internalca: %s is not a PEM certificate", caCertFile)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("internalca: parse CA certificate: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("internalca: %s is not a PEM key", caKeyFile)
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("internalca: parse CA key: %w", err)
	}

	return &CA{Cert: cert, key: key}, nil
}

// EnsureCA loads the CA in dir if one already exists, and creates one
// otherwise. Call this instead of New when the caller does not know
// whether dir already holds a CA from an earlier run.
func EnsureCA(dir string) (*CA, error) {
	if _, err := os.Stat(filepath.Join(dir, caCertFile)); err == nil {
		return Load(dir)
	}
	return New(dir)
}

// IssueCertificate issues a new leaf certificate (ECDSA P-256, SHA-256)
// signed by the CA, valid for days (365 if <= 0), for the given hosts
// (IP addresses and/or DNS names). localhost and 127.0.0.1 are always
// included, as with collector gen-cert's self-signed certificates. It
// returns the leaf's DER-encoded certificate and private key; callers
// decide how to persist them (PEM-encode, write to disk, ...).
func (ca *CA) IssueCertificate(hosts []string, days int) (certDER []byte, key *ecdsa.PrivateKey, err error) {
	if days <= 0 {
		days = 365
	}
	tmpl := &x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "expiry-radar-collector"},
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().Add(time.Duration(days) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		switch {
		case h == "" || h == "localhost" || h == "127.0.0.1":
		case net.ParseIP(h) != nil:
			tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(h))
		case strings.ContainsAny(h, " /:"):
			return nil, nil, fmt.Errorf("%q is not an IP address or DNS name", h)
		default:
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &leafKey.PublicKey, ca.key)
	if err != nil {
		return nil, nil, err
	}
	return der, leafKey, nil
}

func writeFileExcl(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm) // #nosec G304 -- operator-chosen output directory; O_EXCL never overwrites
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	cerr := f.Close()
	return errors.Join(werr, cerr)
}
