package tls

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestChecker_Check_ReturnsCertExpiry(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	port, _ := strconv.Atoi(portStr)

	c := New([]Target{{Host: host, Port: port}})
	// The checker must accept the test server's self-signed cert for this
	// test; inject InsecureSkipVerify via the Checker's TLSConfig field.
	c.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	records, err := c.Check(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	want := srv.Certificate().NotAfter
	if !records[0].ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt = %v, want %v", records[0].ExpiresAt, want)
	}
	if records[0].Kind != "certificate" {
		t.Fatalf("Kind = %q, want %q", records[0].Kind, "certificate")
	}
}

func TestChecker_Check_PartialFailureKeepsOtherResults(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	port, _ := strconv.Atoi(portStr)

	c := New([]Target{
		{Host: host, Port: port},
		{Host: "127.0.0.1", Port: 1}, // nothing listening: unreachable
	})
	c.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	records, err := c.Check(context.Background())
	if err == nil {
		t.Fatal("expected a non-nil error for the unreachable target")
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record from the reachable target, got %d", len(records))
	}
}

// TestChecker_Check_UntrustedCertificateStillReturnsRecord proves the
// checker reports an expiring/expired certificate even when it fails
// chain verification (self-signed, expired, or otherwise untrusted) —
// the most urgent case for an expiry tool must never be silently
// dropped as a "connection error".
func TestChecker_Check_UntrustedCertificateStillReturnsRecord(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	port, _ := strconv.Atoi(portStr)

	c := New([]Target{{Host: host, Port: port}})
	// No TLSConfig set: the test server's cert is self-signed and would
	// fail default chain verification, exactly like an expired or
	// otherwise untrusted certificate would.
	records, err := c.Check(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record despite verification failure, got %d", len(records))
	}
	if records[0].Metadata["verify_error"] == "" {
		t.Fatal("expected verify_error metadata to record the verification failure")
	}
}

// TestChecker_dialConfig_AlwaysSetsServerNameForSMTPTargets proves the
// fix for a real bug: the SMTP STARTTLS path used to pass the
// Checker's (often nil) TLSConfig straight into
// smtp.Client.StartTLS, which errors with "tls: either ServerName or
// InsecureSkipVerify must be specified" whenever the target is
// addressed by bare host/IP and no TLSConfig override is set — i.e.
// on every default-configured SMTP target. dialConfig is what both
// the direct-TLS and STARTTLS paths now use to build their tls.Config,
// and it must always carry a non-empty ServerName (and
// InsecureSkipVerify, so an expired/self-signed cert never blocks the
// connection — see TestChecker_Check_UntrustedCertificateStillReturnsRecord).
func TestChecker_dialConfig_AlwaysSetsServerNameForSMTPTargets(t *testing.T) {
	c := New(nil)
	cfg := c.dialConfig("mail.example.com")

	if cfg.ServerName != "mail.example.com" {
		t.Fatalf("ServerName = %q, want %q", cfg.ServerName, "mail.example.com")
	}
	if !cfg.InsecureSkipVerify {
		t.Fatal("expected InsecureSkipVerify to be true")
	}
}
