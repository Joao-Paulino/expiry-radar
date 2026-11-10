package server_test

import (
	"crypto/tls"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/Joao-Paulino/expiry-radar/internal/auth"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/server"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/testhelpers"
)

// TestRun_DashboardRequiresAdminToken proves the dashboard (and its
// mute/export endpoints) cannot be read or written by anyone who can
// merely reach the Collector's ingest endpoint — a separate admin
// token, distinct from the agents' ingest AuthTokens, must be
// required.
func TestRun_DashboardRequiresAdminToken(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := testhelpers.WriteSelfSignedCertForTest(t, dir)
	cfg := server.Config{
		DBPath:      filepath.Join(dir, "radar.db"),
		ListenAddr:  "127.0.0.1:0",
		AuthTokens:  []string{"agent-token"},
		AdminTokens: []string{"admin-token"},
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
	}
	addr, stop, err := testhelpers.StartForTest(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}

	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated dashboard request: got %d, want 401", resp.StatusCode)
	}

	req, _ := http.NewRequest("GET", "https://"+addr+"/", nil)
	auth.AttachToken(req, "admin-token")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticated dashboard request: got %d, want 200", resp.StatusCode)
	}

	// An agent ingest token must not also work as an admin token.
	req2, _ := http.NewRequest("GET", "https://"+addr+"/", nil)
	auth.AttachToken(req2, "agent-token")
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("dashboard request with an agent ingest token: got %d, want 401", resp2.StatusCode)
	}
}
