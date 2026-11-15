package local

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func selfSigned(t *testing.T, cn string, dns ...string) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now(), NotAfter: time.Now().Add(90 * 24 * time.Hour), DNSNames: dns}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestFileChecker(t *testing.T) {
	dir := t.TempDir()
	a, b := selfSigned(t, "www.example.com", "www.example.com"), selfSigned(t, "www.example.com")
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})...)
	os.WriteFile(filepath.Join(dir, "site.pem"), chain, 0o644)
	os.WriteFile(filepath.Join(dir, "one.der"), selfSigned(t, "der.example"), 0o644)
	os.WriteFile(filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1, 2, 3}}), 0o600)
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("ignored"), 0o644)
	os.MkdirAll(filepath.Join(dir, "sub"), 0o755)
	os.WriteFile(filepath.Join(dir, "sub", "x.crt"), []byte("garbage"), 0o644)

	c := Checkers(&Config{CertPaths: []string{dir}})[0]
	recs, err := c.Check(context.Background())
	if err == nil || !strings.Contains(err.Error(), "x.crt") {
		t.Fatalf("garbage .crt must be an error, got %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("want 3 records (2 in chain + der), got %d: %+v", len(recs), recs)
	}
	names := map[string]bool{}
	for _, r := range recs {
		names[r.Name] = true
		if r.Kind != "certificate" || !strings.HasPrefix(r.Source, "file://") || r.ExpiresAt.IsZero() || r.Metadata["thumbprint"] == "" {
			t.Errorf("bad record %+v", r)
		}
	}
	if names["www.example.com"] || !names["der.example"] {
		t.Errorf("duplicate CNs must get a thumbprint suffix: %v", names)
	}

	// A missing path is an error but does not hide the other results.
	c = Checkers(&Config{CertPaths: []string{filepath.Join(dir, "one.der"), filepath.Join(dir, "nope")}})[0]
	recs, err = c.Check(context.Background())
	if err == nil || len(recs) != 1 {
		t.Fatalf("missing path: %d %v", len(recs), err)
	}
}

func TestConfigValidate(t *testing.T) {
	if (&Config{CertPaths: []string{" "}}).Validate() == nil || (&Config{WindowsCertStores: []string{`Root\x`}}).Validate() == nil {
		t.Error("bad config accepted")
	}
	if (&Config{}).Validate() != nil || (*Config)(nil).Validate() != nil {
		t.Error("empty config rejected")
	}
	if Checkers(&Config{}) != nil && len(Checkers(&Config{})) != 1 {
		t.Error("empty config should enable only the Windows store checker, on Windows")
	}
}
