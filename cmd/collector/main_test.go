package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/auth"
	"github.com/Joao-Paulino/expiry-radar/internal/checker"
)

// writeSelfSignedCertForTest generates a short-lived self-signed
// certificate/key pair and writes it to dir, returning the cert and
// key file paths.
func writeSelfSignedCertForTest(t *testing.T, dir string) (certFile, keyFile string) {
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

// startForTest wraps run() in a goroutine and returns the bound
// address and a shutdown func, for tests that need to exercise the
// collector over HTTPS without a fixed port.
func startForTest(cfg Config) (addr string, stop func(), err error) {
	ready := make(chan string, 1)
	done := make(chan struct{})
	cfg.Ready = ready
	cfg.Done = done

	runErr := make(chan error, 1)
	go func() {
		runErr <- run(cfg)
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

func TestRun_ServesIngestAndDashboardOverHTTPS(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeSelfSignedCertForTest(t, dir) // test helper: generates a short-lived self-signed cert/key pair to disk
	cfg := Config{
		DBPath:      filepath.Join(dir, "radar.db"),
		ListenAddr:  "127.0.0.1:0", // run() must report the actual bound port, e.g. via a channel/field for the test to use
		AuthTokens:  []string{"test-token"},
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
	}
	addr, stop, err := startForTest(cfg) // small test-only helper in main_test.go wrapping run() to return the bound address and a shutdown func
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	batch := checker.Batch{AgentID: "agent-1", Results: []checker.Result{{CheckerName: "tls-checker", Records: []checker.ExpiryRecord{{Source: "a", Name: "b", Kind: "certificate", ExpiresAt: time.Now().Add(48 * time.Hour)}}}}}
	body, _ := json.Marshal(batch)
	req, _ := http.NewRequest("POST", "https://"+addr+"/ingest", bytes.NewReader(body))
	auth.AttachToken(req, "test-token")
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("ingest: err=%v status=%v", err, resp)
	}

	dashResp, err := client.Get("https://" + addr + "/")
	if err != nil || dashResp.StatusCode != http.StatusOK {
		t.Fatalf("dashboard: err=%v status=%v", err, dashResp)
	}
}
