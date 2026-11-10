package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/auth"
	"github.com/Joao-Paulino/expiry-radar/internal/checker"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/testhelpers"
)

func TestRun_ServesIngestAndDashboardOverHTTPS(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := testhelpers.WriteSelfSignedCertForTest(t, dir)
	cfg := Config{
		DBPath:      filepath.Join(dir, "radar.db"),
		ListenAddr:  "127.0.0.1:0", // run() must report the actual bound port, e.g. via a channel/field for the test to use
		AuthTokens:  []string{"test-token"},
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
	batch := checker.Batch{AgentID: "agent-1", Results: []checker.Result{{CheckerName: "tls-checker", Records: []checker.ExpiryRecord{{Source: "a", Name: "b", Kind: "certificate", ExpiresAt: time.Now().Add(48 * time.Hour)}}}}}
	body, _ := json.Marshal(batch)
	req, _ := http.NewRequest("POST", "https://"+addr+"/ingest", bytes.NewReader(body))
	auth.AttachToken(req, "test-token")
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("ingest: err=%v status=%v", err, resp)
	}

	dashReq, _ := http.NewRequest("GET", "https://"+addr+"/", nil)
	auth.AttachToken(dashReq, "admin-token")
	dashResp, err := client.Do(dashReq)
	if err != nil || dashResp.StatusCode != http.StatusOK {
		t.Fatalf("dashboard: err=%v status=%v", err, dashResp)
	}
}
