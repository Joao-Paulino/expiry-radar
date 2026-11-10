// Package testhelpers provides shared test-only helpers for starting
// a real Collector server and generating a self-signed TLS
// certificate/key pair, used by both cmd/collector's own tests and
// the end-to-end test in test/e2e.
package testhelpers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/collector/server"
)

// WriteSelfSignedCertForTest generates a short-lived self-signed
// certificate/key pair and writes it to dir, returning the cert and
// key file paths.
func WriteSelfSignedCertForTest(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")

	certOut, err := os.Create(certFile)
	if err != nil {
		t.Fatalf("create cert file: %v", err)
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("encode cert: %v", err)
	}

	keyOut, err := os.Create(keyFile)
	if err != nil {
		t.Fatalf("create key file: %v", err)
	}
	defer keyOut.Close()
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		t.Fatalf("encode key: %v", err)
	}

	return certFile, keyFile
}

// StartForTest wraps server.Run in a goroutine and returns the bound
// address and a shutdown func, for tests that need to exercise the
// Collector over HTTPS without a fixed port.
func StartForTest(cfg server.Config) (addr string, stop func(), err error) {
	ready := make(chan string, 1)
	done := make(chan struct{})
	cfg.Ready = ready
	cfg.Done = done

	runErr := make(chan error, 1)
	go func() {
		runErr <- server.Run(cfg)
	}()

	select {
	case addr = <-ready:
	case e := <-runErr:
		return "", nil, e
	case <-time.After(5 * time.Second):
		return "", nil, context.DeadlineExceeded
	}

	stop = func() {
		close(done)
		<-runErr
	}
	return addr, stop, nil
}
