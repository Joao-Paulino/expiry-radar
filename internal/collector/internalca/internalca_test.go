package internalca

import (
	"bytes"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestNew_WritesARootCA(t *testing.T) {
	dir := t.TempDir()

	ca, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !ca.Cert.IsCA {
		t.Fatal("want IsCA true")
	}
	if ca.Cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatal("want KeyUsageCertSign set")
	}
	for _, p := range []string{filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected %s to exist: %v", p, err)
		}
	}
}

func TestNew_RefusesToOverwriteAnExistingCA(t *testing.T) {
	dir := t.TempDir()
	if _, err := New(dir); err != nil {
		t.Fatalf("first New: %v", err)
	}
	if _, err := New(dir); err == nil {
		t.Fatal("want New to refuse a directory that already has a CA")
	}
}

func TestLoad_RoundTripsWhatNewWrote(t *testing.T) {
	dir := t.TempDir()
	created, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !bytes.Equal(loaded.Cert.Raw, created.Cert.Raw) {
		t.Fatal("Load did not return the same CA certificate New wrote")
	}
}

func TestLoad_MissingCAFails(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(dir); err == nil {
		t.Fatal("want an error when no CA exists yet")
	}
}

func TestEnsureCA_CreatesThenReuses(t *testing.T) {
	dir := t.TempDir()

	first, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("first EnsureCA: %v", err)
	}
	second, err := EnsureCA(dir)
	if err != nil {
		t.Fatalf("second EnsureCA: %v", err)
	}
	if !bytes.Equal(first.Cert.Raw, second.Cert.Raw) {
		t.Fatal("want EnsureCA to reuse the existing CA, not regenerate it")
	}
}

func TestIssueCertificate_LeafVerifiesAgainstTheCA(t *testing.T) {
	dir := t.TempDir()
	ca, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	certDER, _, err := ca.IssueCertificate([]string{"collector.example.com", "10.0.0.10"}, 365)
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if leaf.IsCA {
		t.Fatal("want the issued leaf to not itself be a CA")
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "collector.example.com", Roots: roots}); err != nil {
		t.Fatalf("leaf does not verify against the issuing CA: %v", err)
	}

	wantIP := net.ParseIP("10.0.0.10")
	found := false
	for _, ip := range leaf.IPAddresses {
		if ip.Equal(wantIP) {
			found = true
		}
	}
	if !found {
		t.Fatalf("leaf.IPAddresses = %v, want to include %s", leaf.IPAddresses, wantIP)
	}
}

func TestIssueCertificate_AlwaysIncludesLocalhost(t *testing.T) {
	dir := t.TempDir()
	ca, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	certDER, _, err := ca.IssueCertificate(nil, 365)
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "localhost", Roots: roots}); err != nil {
		t.Fatalf("leaf does not verify for localhost: %v", err)
	}
}

func TestIssueCertificate_RejectsAHostThatIsNeitherAnIPNorADNSName(t *testing.T) {
	dir := t.TempDir()
	ca, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, _, err := ca.IssueCertificate([]string{"not a host"}, 365); err == nil {
		t.Fatal("want an error for an invalid host")
	}
}
