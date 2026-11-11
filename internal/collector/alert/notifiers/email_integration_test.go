//go:build integration

package notifiers

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/collector/alert"
)

// TestIntegration_EmailSTARTTLS sends a real alert through a real SMTP
// server that requires STARTTLS (Mailpit in CI) and checks it arrived.
func TestIntegration_EmailSTARTTLS(t *testing.T) {
	addr, caFile, api := os.Getenv("SMTP_TEST_ADDR"), os.Getenv("SMTP_TEST_CA"), os.Getenv("MAILPIT_API")
	if addr == "" {
		t.Skip("SMTP_TEST_ADDR not set")
	}
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)
	pem, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem)

	e := NewEmail(EmailConfig{SMTPHost: host, SMTPPort: port, From: "radar@example.com", To: "oncall@example.com"})
	e.rootCAs = roots
	if err := e.Send(context.Background(), alert.Notification{Type: alert.TypeAgentSilent, Severity: alert.SeverityCritical, Agent: "smoke"}); err != nil {
		t.Fatalf("send over STARTTLS: %v", err)
	}

	var got struct {
		Total int `json:"total"`
	}
	for i := 0; i < 20 && got.Total == 0; i++ {
		resp, err := http.Get(api + "/api/v1/messages")
		if err == nil {
			json.NewDecoder(resp.Body).Decode(&got)
			resp.Body.Close()
		}
		time.Sleep(250 * time.Millisecond)
	}
	if got.Total < 1 {
		t.Fatal("message not received by the SMTP server")
	}
}
