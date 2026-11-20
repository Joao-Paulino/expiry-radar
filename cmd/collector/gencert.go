package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/collector/internalca"
)

// runGenCert writes a TLS certificate for the collector: collector.crt
// and collector.key in dir. hosts are the IP addresses and DNS names
// agents will use; localhost and 127.0.0.1 are always included. It
// never overwrites existing files: a key that is already in use by
// agents must not change by accident.
//
// When caDir is empty, the certificate is self-signed (ECDSA P-256,
// SHA-256), as before: agents must trust collector.crt itself.
//
// When caDir is set, the certificate is issued by a reusable internal
// CA kept in caDir (created there if it doesn't exist yet, M14: a
// fallback for installations with no public domain for Let's
// Encrypt). In this mode agents must trust caDir/ca.crt instead —
// collector.crt is now a leaf certificate, not a root of trust — which
// lets the installer issue more certificates later from the same CA
// without redistributing trust to every agent again.
func runGenCert(dir string, hosts []string, days int, caDir string, out io.Writer) error {
	if days <= 0 {
		days = 365
	}
	certPath, keyPath := filepath.Join(dir, "collector.crt"), filepath.Join(dir, "collector.key")
	for _, p := range []string{certPath, keyPath} {
		if _, err := os.Stat(p); err == nil {
			return fmt.Errorf("%s already exists; remove it first if you really want a new certificate", p)
		}
	}

	if caDir != "" {
		return runGenCertFromCA(dir, certPath, keyPath, hosts, days, caDir, out)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          new(big.Int).SetInt64(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "expiry-radar-collector"},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(time.Duration(days) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		switch {
		case h == "" || h == "localhost" || h == "127.0.0.1":
		case net.ParseIP(h) != nil:
			tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(h))
		case strings.ContainsAny(h, " /:"):
			return fmt.Errorf("%q is not an IP address or DNS name", h)
		default:
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if err := writeFileExcl(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	if err := writeFileExcl(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		_ = os.Remove(keyPath) // best effort: never leave a key without its certificate
		return err
	}
	fmt.Fprintf(out, "Wrote %s and %s (valid %d days) for %s\n", certPath, keyPath, days,
		strings.Join(append(tmpl.DNSNames, ipStrings(tmpl.IPAddresses)...), ", "))
	fmt.Fprintln(out, "Copy collector.crt to every agent (collector_ca_file). Keep collector.key private.")
	return nil
}

// runGenCertFromCA issues the collector's leaf certificate from the
// internal CA in caDir (created there if missing) instead of
// self-signing, and writes it to certPath/keyPath.
func runGenCertFromCA(dir, certPath, keyPath string, hosts []string, days int, caDir string, out io.Writer) error {
	ca, err := internalca.EnsureCA(caDir)
	if err != nil {
		return err
	}
	certDER, key, err := ca.IssueCertificate(hosts, days)
	if err != nil {
		return err
	}
	if days <= 0 {
		days = 365
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if err := writeFileExcl(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	if err := writeFileExcl(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o644); err != nil {
		_ = os.Remove(keyPath) // best effort: never leave a key without its certificate
		return err
	}
	fmt.Fprintf(out, "Wrote %s and %s (valid %d days), issued by the internal CA in %s\n", certPath, keyPath, days, caDir)
	fmt.Fprintf(out, "Copy %s to every agent (collector_ca_file) — NOT %s: agents must trust the CA, not this leaf certificate.\n",
		filepath.Join(caDir, "ca.crt"), filepath.Base(certPath))
	fmt.Fprintln(out, "Keep collector.key and the CA's own key (ca.key in the CA directory) private.")
	return nil
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

func ipStrings(ips []net.IP) []string {
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.String()
	}
	return out
}

// parseGenCertArgs handles:
// gen-cert <dir> [--host a,b,...] [--days N] [--ca <ca-dir>]
func parseGenCertArgs(args []string) (dir string, hosts []string, days int, caDir string, err error) {
	if len(args) < 1 {
		return "", nil, 0, "", errors.New("usage: collector gen-cert <dir> [--host ip,dns,...] [--days N] [--ca <ca-dir>]")
	}
	dir = args[0]
	for i := 1; i < len(args); i++ {
		switch {
		case args[i] == "--host" && i+1 < len(args):
			i++
			hosts = append(hosts, strings.Split(args[i], ",")...)
		case args[i] == "--days" && i+1 < len(args):
			i++
			if _, e := fmt.Sscanf(args[i], "%d", &days); e != nil || days <= 0 || days > 3650 {
				return "", nil, 0, "", fmt.Errorf("--days must be 1..3650")
			}
		case args[i] == "--ca" && i+1 < len(args):
			i++
			caDir = args[i]
		default:
			return "", nil, 0, "", fmt.Errorf("unknown argument %q", args[i])
		}
	}
	return dir, hosts, days, caDir, nil
}
