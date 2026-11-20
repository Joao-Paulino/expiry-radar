package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGenCert(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	if err := runGenCert(dir, []string{"192.168.1.10", "radar.example.local", " "}, 0, "", &out); err != nil {
		t.Fatal(err)
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "collector.crt"), filepath.Join(dir, "collector.key"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	for _, h := range []string{"192.168.1.10", "127.0.0.1", "localhost", "radar.example.local"} {
		if err := leaf.VerifyHostname(h); err != nil {
			t.Errorf("%s: %v", h, err)
		}
	}
	// Unix permissions only; on Windows the installer applies ACLs.
	if fi, _ := os.Stat(filepath.Join(dir, "collector.key")); runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("key is readable by others: %v", fi.Mode())
	}
	// Never silently replaces a key agents may already trust.
	if err := runGenCert(dir, nil, 0, "", &out); err == nil {
		t.Error("second gen-cert must refuse to overwrite")
	}
	if err := runGenCert(t.TempDir(), []string{"https://x"}, 0, "", &out); err == nil {
		t.Error("a URL is not a host")
	}
}

func TestParseGenCertArgs(t *testing.T) {
	dir, hosts, days, caDir, err := parseGenCertArgs([]string{"C:\\x", "--host", "10.0.0.1,r.local", "--days", "30", "--ca", "C:\\ca"})
	if err != nil || dir != "C:\\x" || len(hosts) != 2 || days != 30 || caDir != "C:\\ca" {
		t.Fatalf("%q %v %d %q %v", dir, hosts, days, caDir, err)
	}
	for _, bad := range [][]string{{}, {"d", "--days", "0"}, {"d", "--what"}} {
		if _, _, _, _, err := parseGenCertArgs(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

// TestGenCert_WithInternalCA proves gen-cert can issue the collector's
// certificate from a reusable internal CA (--ca <dir>) instead of a
// bare self-signed leaf — M14, part 2: a fallback for installations
// with no public domain for Let's Encrypt.
func TestGenCert_WithInternalCA(t *testing.T) {
	certDir, caDir := t.TempDir(), t.TempDir()
	var out bytes.Buffer
	if err := runGenCert(certDir, []string{"10.0.0.10", "radar.example.local"}, 0, caDir, &out); err != nil {
		t.Fatalf("runGenCert with --ca: %v", err)
	}

	cert, err := tls.LoadX509KeyPair(filepath.Join(certDir, "collector.crt"), filepath.Join(certDir, "collector.key"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.IsCA {
		t.Fatal("the issued leaf must not itself be a CA")
	}

	caCert, err := x509.ParseCertificate(mustReadFirstPEM(t, filepath.Join(caDir, "ca.crt")))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "radar.example.local", Roots: roots}); err != nil {
		t.Fatalf("issued leaf does not verify against the CA in %s: %v", caDir, err)
	}

	// A second run reuses the same CA (does not regenerate it) and
	// issues a second certificate from it rather than refusing like
	// the self-signed path does.
	certDir2 := t.TempDir()
	if err := runGenCert(certDir2, []string{"10.0.0.20"}, 0, caDir, &out); err != nil {
		t.Fatalf("second runGenCert with the same --ca: %v", err)
	}
	cert2, err := tls.LoadX509KeyPair(filepath.Join(certDir2, "collector.crt"), filepath.Join(certDir2, "collector.key"))
	if err != nil {
		t.Fatal(err)
	}
	leaf2, _ := x509.ParseCertificate(cert2.Certificate[0])
	if _, err := leaf2.Verify(x509.VerifyOptions{DNSName: "10.0.0.20", Roots: roots}); err != nil {
		t.Fatalf("second issued leaf does not verify against the same CA: %v", err)
	}
}

func mustReadFirstPEM(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- test reading its own t.TempDir() output
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("%s is not PEM", path)
	}
	return block.Bytes
}
