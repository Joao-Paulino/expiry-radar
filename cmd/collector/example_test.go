package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/collector/server"
)

// examples/collector.full.json documents every option; it must stay a
// valid config with no unknown or misspelled field.
func TestExampleConfigIsValid(t *testing.T) {
	b, err := os.ReadFile("../../examples/collector.full.json")
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(withLocalFiles(t, b)))
	dec.DisallowUnknownFields()
	var cfg server.Config
	if err := dec.Decode(&cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

// withLocalFiles points every /etc/expiry-radar/ path in the example at a
// temp dir holding stand-in files (a real PEM certificate for *.pem), so
// Validate can open them.
func withLocalFiles(t *testing.T, b []byte) []byte {
	t.Helper()
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example CA"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	for _, m := range regexp.MustCompile(`/etc/expiry-radar/[A-Za-z0-9._-]+`).FindAll(b, -1) {
		name := filepath.Join(dir, filepath.Base(string(m)))
		content := []byte("example-secret")
		if strings.HasSuffix(name, ".pem") || strings.HasSuffix(name, ".crt") {
			content = pemCert
		}
		if err := os.WriteFile(name, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return bytes.ReplaceAll(b, []byte("/etc/expiry-radar/"), []byte(filepath.ToSlash(dir)+"/"))
}
