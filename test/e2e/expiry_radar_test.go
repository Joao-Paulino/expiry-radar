// Package e2e proves the full Agent -> Collector -> Dashboard flow for
// the TLS checker, end to end, against real network connections (a
// real HTTPS Collector server and a real HTTPS target server), not
// mocks.
package e2e

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/agent"
	"github.com/Joao-Paulino/expiry-radar/internal/auth"
	"github.com/Joao-Paulino/expiry-radar/internal/checker"
	tlschecker "github.com/Joao-Paulino/expiry-radar/internal/checker/tls"
	collector "github.com/Joao-Paulino/expiry-radar/internal/collector/server"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/testhelpers"
)

func TestEndToEnd_CertExpiryFlowsFromAgentToDashboard(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := testhelpers.WriteSelfSignedCertForTest(t, dir)
	collectorAddr, stopCollector, err := testhelpers.StartForTest(collector.Config{
		DBPath:        filepath.Join(dir, "radar.db"),
		ListenAddr:    "127.0.0.1:0",
		AuthTokens:    []string{"e2e-agent-token-0123456789abcdef0123"},
		AdminTokens:   []string{"e2e-admin-token-0123456789abcdef0123"},
		TLSCertFile:   certFile,
		TLSKeyFile:    keyFile,
		AlertInterval: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stopCollector()

	// A target TLS server for the agent's checker to scan.
	targetSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer targetSrv.Close()
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(targetSrv.URL, "https://"))
	port, _ := strconv.Atoi(portStr)

	tlsChecker := tlschecker.New([]tlschecker.Target{{Host: host, Port: port}})
	// targetSrv's certificate is self-signed; the checker's TLSConfig
	// field exists precisely for this test-injection purpose (see
	// internal/checker/tls's own tests).
	tlsChecker.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	pusher := agent.NewPusher("https://"+collectorAddr, "e2e-agent-token-0123456789abcdef0123")
	// The Pusher's http.Client must trust the Collector's self-signed test
	// cert; set this via the same InsecureSkipVerify pattern used in Task 17's test.
	pusher.HTTPClient().Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	runner := agent.NewRunner("e2e-agent", []checker.Checker{tlsChecker}, pusher, agent.NewQueue(filepath.Join(dir, "queue.jsonl")))

	if err := runner.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce failed: %v", err)
	}

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	exportReq, _ := http.NewRequest("GET", "https://"+collectorAddr+"/export.json", nil)
	auth.AttachToken(exportReq, "e2e-admin-token-0123456789abcdef0123")
	resp, err := client.Do(exportReq)
	if err != nil {
		t.Fatal(err)
	}
	var records []map[string]any
	json.NewDecoder(resp.Body).Decode(&records)
	if len(records) != 1 {
		t.Fatalf("expected 1 exported record after the agent's push, got %d", len(records))
	}
	if records[0]["source"] != fmt.Sprintf("%s:%d", host, port) {
		t.Fatalf("got %+v", records[0])
	}
}
