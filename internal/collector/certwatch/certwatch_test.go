package certwatch

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeCert generates a short-lived self-signed ECDSA certificate and
// writes it to certFile/keyFile, returning the raw DER bytes of the
// leaf certificate so tests can tell two generated certificates
// apart by comparing bytes.
func writeCert(t *testing.T, certFile, keyFile string) (der []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "collector-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err = x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certOut, err := os.Create(certFile) // #nosec G304 -- test helper writing into t.TempDir()
	if err != nil {
		t.Fatalf("create cert file: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("encode cert: %v", err)
	}
	certOut.Close()

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- test helper writing into t.TempDir()
	if err != nil {
		t.Fatalf("create key file: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		t.Fatalf("encode key: %v", err)
	}
	keyOut.Close()

	return der
}

// bump sets both files' modification time strictly later than
// whatever they currently have, so Reload reliably sees a change
// even on filesystems with coarse mtime resolution.
func bump(t *testing.T, certFile, keyFile string, at time.Time) {
	t.Helper()
	if err := os.Chtimes(certFile, at, at); err != nil {
		t.Fatalf("chtimes cert: %v", err)
	}
	if err := os.Chtimes(keyFile, at, at); err != nil {
		t.Fatalf("chtimes key: %v", err)
	}
}

func TestNew_LoadsCertificate(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	der := writeCert(t, certFile, keyFile)

	w, err := New(certFile, keyFile)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cert, err := w.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if !bytes.Equal(cert.Certificate[0], der) {
		t.Fatal("GetCertificate did not return the certificate New loaded")
	}
}

func TestNew_MissingFileFails(t *testing.T) {
	dir := t.TempDir()
	if _, err := New(filepath.Join(dir, "missing-cert.pem"), filepath.Join(dir, "missing-key.pem")); err == nil {
		t.Fatal("want an error for missing files, got nil")
	}
}

func TestReload_PicksUpChangedFiles(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writeCert(t, certFile, keyFile)

	w, err := New(certFile, keyFile)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	newDER := writeCert(t, certFile, keyFile)
	bump(t, certFile, keyFile, time.Now().Add(time.Hour))

	reloaded, err := w.Reload()
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if !reloaded {
		t.Fatal("want Reload to report a reload after the files changed")
	}
	cert, _ := w.GetCertificate(nil)
	if !bytes.Equal(cert.Certificate[0], newDER) {
		t.Fatal("GetCertificate did not return the reloaded certificate")
	}
}

func TestReload_NoChangeReturnsFalse(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writeCert(t, certFile, keyFile)

	w, err := New(certFile, keyFile)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	reloaded, err := w.Reload()
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if reloaded {
		t.Fatal("want no reload when the files did not change")
	}
}

func TestReload_KeepsServingOldCertOnBadNewPair(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	oldDER := writeCert(t, certFile, keyFile)

	w, err := New(certFile, keyFile)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Simulate a renewal that only wrote a fresh (empty/invalid) cert
	// file so far: the key still matches the old certificate.
	if err := os.WriteFile(certFile, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write bad cert: %v", err)
	}
	bump(t, certFile, keyFile, time.Now().Add(time.Hour))

	reloaded, err := w.Reload()
	if err == nil {
		t.Fatal("want an error for an invalid certificate")
	}
	if reloaded {
		t.Fatal("want reloaded=false when Reload fails")
	}
	cert, _ := w.GetCertificate(nil)
	if !bytes.Equal(cert.Certificate[0], oldDER) {
		t.Fatal("want GetCertificate to keep returning the old, still-valid certificate")
	}
}

func TestWatch_AppliesReloadsUntilDone(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writeCert(t, certFile, keyFile)

	w, err := New(certFile, keyFile)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	newDER := writeCert(t, certFile, keyFile)
	bump(t, certFile, keyFile, time.Now().Add(time.Hour))

	done := make(chan struct{})
	watchDone := make(chan struct{})
	go func() {
		w.Watch(10*time.Millisecond, done, nil)
		close(watchDone)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		cert, _ := w.GetCertificate(nil)
		if bytes.Equal(cert.Certificate[0], newDER) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cert, _ := w.GetCertificate(nil)
	if !bytes.Equal(cert.Certificate[0], newDER) {
		t.Fatal("Watch did not pick up the changed certificate in time")
	}

	close(done)
	select {
	case <-watchDone:
	case <-time.After(time.Second):
		t.Fatal("Watch did not stop after done was closed")
	}
}
