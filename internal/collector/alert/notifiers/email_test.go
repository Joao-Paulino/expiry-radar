package notifiers

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/alert"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/store"
)

// fakeSMTPServer scripts a minimal SMTP exchange. ehloExts are extra
// EHLO lines (e.g. "STARTTLS"); every command received is sent to seen.
func fakeSMTPServer(conn net.Conn, ehloExts []string, seen chan<- string) {
	write := func(s string) { conn.Write([]byte(s + "\r\n")) }
	reader := bufio.NewReader(conn)

	write("220 fake.smtp.local ESMTP")
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		if seen != nil {
			seen <- line
		}
		switch {
		case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "HELO"):
			if len(ehloExts) == 0 {
				write("250 fake.smtp.local")
				continue
			}
			write("250-fake.smtp.local")
			for i, ext := range ehloExts {
				if i == len(ehloExts)-1 {
					write("250 " + ext)
				} else {
					write("250-" + ext)
				}
			}
		case strings.HasPrefix(line, "AUTH"):
			write("235 Authentication successful")
		case strings.HasPrefix(line, "MAIL FROM"), strings.HasPrefix(line, "RCPT TO"):
			write("250 OK")
		case strings.HasPrefix(line, "DATA"):
			write("354 End data with <CR><LF>.<CR><LF>")
			for {
				dataLine, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimSpace(dataLine) == "." {
					break
				}
			}
			write("250 OK")
		case strings.HasPrefix(line, "QUIT"):
			write("221 Bye")
			return
		default:
			write("250 OK")
		}
	}
}

func testNotification() alert.Notification {
	return alert.Notification{Severity: "critical", Record: store.StoredRecord{ExpiryRecord: checker.ExpiryRecord{Source: "a", Name: "b"}}}
}

// TestEmail_Send_ImplicitTLSWithAuth proves security "tls" (port 465
// style) encrypts the whole session and logs in before sending.
func TestEmail_Send_ImplicitTLSWithAuth(t *testing.T) {
	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS() // only to obtain a self-signed certificate and its pool
	cert := srv.TLS.Certificates[0]
	roots := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	srv.Close()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	seen := make(chan string, 50)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		fakeSMTPServer(conn, []string{"AUTH PLAIN"}, seen)
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	e := NewEmail(EmailConfig{SMTPHost: host, SMTPPort: port, Security: "tls", Username: "radar", Password: "pw", From: "radar@example.com", To: "oncall@example.com"})
	e.rootCAs = roots
	if err := e.Send(context.Background(), testNotification()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	<-done
	close(seen)
	var authed bool
	for cmd := range seen {
		if strings.HasPrefix(cmd, "AUTH PLAIN") {
			authed = true
		}
	}
	if !authed {
		t.Fatal("client never authenticated")
	}
}

// TestEmail_Send_RefusesPlaintextWhenStartTLSMissing proves the default
// (starttls) mode never falls back to sending mail unencrypted when the
// server does not offer STARTTLS.
func TestEmail_Send_RefusesPlaintextWhenStartTLSMissing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	seen := make(chan string, 50)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		fakeSMTPServer(conn, nil, seen)
		close(seen)
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	e := NewEmail(EmailConfig{SMTPHost: host, SMTPPort: port, From: "radar@example.com", To: "oncall@example.com"})
	if err := e.Send(context.Background(), testNotification()); err == nil {
		t.Fatal("expected an error: server offers no STARTTLS")
	}
	for cmd := range seen {
		if strings.HasPrefix(cmd, "MAIL FROM") || strings.HasPrefix(cmd, "AUTH") {
			t.Fatalf("sent %q over an unencrypted connection", cmd)
		}
	}
}

// TestEmailConfig_Validate_RejectsUnknownSecurity proves a typo in
// security fails at startup instead of at the first alert.
func TestEmailConfig_Validate_RejectsUnknownSecurity(t *testing.T) {
	for _, ok := range []string{"", "starttls", "tls"} {
		if err := (EmailConfig{SMTPHost: "h", Security: ok}).Validate(); err != nil {
			t.Errorf("security %q rejected: %v", ok, err)
		}
	}
	if err := (EmailConfig{SMTPHost: "h", Security: "none"}).Validate(); err == nil {
		t.Error("security \"none\" must be rejected")
	}
}

// TestEmail_Send_DoesNotHangForever proves Send bounds the whole SMTP
// exchange with a deadline: one unreachable/unresponsive notifier
// must not block every other alert from ever being attempted (Review
// Focus #4), which a bare net/smtp.SendMail call — with no deadline
// and ignoring ctx — cannot guarantee.
func TestEmail_Send_DoesNotHangForever(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Accept the connection but never send the greeting or
		// anything else — simulate a hung relay.
		select {}
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	e := NewEmail(EmailConfig{SMTPHost: host, SMTPPort: port, From: "radar@example.com", To: "oncall@example.com"})
	e.timeout = 200 * time.Millisecond

	done := make(chan error, 1)
	go func() {
		done <- e.Send(context.Background(), alert.Notification{Record: store.StoredRecord{ExpiryRecord: checker.ExpiryRecord{Source: "a", Name: "b"}}})
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected a timeout error from the unresponsive relay")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Send did not bound the exchange with a deadline — it hung")
	}
}

// TestEmail_Send_SanitizesCRLFInRecordName proves a certificate's
// Subject CN (attacker-controlled: it comes straight from the
// scanned server's certificate) cannot inject extra SMTP headers,
// such as a Bcc, via embedded CR/LF.
func TestEmail_Send_SanitizesCRLFInRecordName(t *testing.T) {
	if got := sanitizeHeaderValue("evil\r\nBcc: attacker@example.com"); strings.Contains(got, "\r") || strings.Contains(got, "\n") {
		t.Fatalf("sanitizeHeaderValue left a CR/LF in: %q", got)
	}
}
