package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestGenCert(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	if err := runGenCert(dir, []string{"192.168.1.10", "radar.example.local", " "}, 0, &out); err != nil {
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
	if fi, _ := os.Stat(filepath.Join(dir, "collector.key")); fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("key is readable by others: %v", fi.Mode())
	}
	// Never silently replaces a key agents may already trust.
	if err := runGenCert(dir, nil, 0, &out); err == nil {
		t.Error("second gen-cert must refuse to overwrite")
	}
	if err := runGenCert(t.TempDir(), []string{"https://x"}, 0, &out); err == nil {
		t.Error("a URL is not a host")
	}
}

func TestParseGenCertArgs(t *testing.T) {
	dir, hosts, days, err := parseGenCertArgs([]string{"C:\\x", "--host", "10.0.0.1,r.local", "--days", "30"})
	if err != nil || dir != "C:\\x" || len(hosts) != 2 || days != 30 {
		t.Fatalf("%q %v %d %v", dir, hosts, days, err)
	}
	for _, bad := range [][]string{{}, {"d", "--days", "0"}, {"d", "--what"}} {
		if _, _, _, err := parseGenCertArgs(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}
