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
