package notifiers

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/alert"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/store"
)

// fakeSMTPServer scripts the minimal 220/250/354/250/221 exchange that
// net/smtp.SendMail performs without authentication, so Email.Send can
// be proven to actually dial and speak SMTP rather than silently
// succeed.
func fakeSMTPServer(conn net.Conn) {
	write := func(s string) { conn.Write([]byte(s + "\r\n")) }
	reader := bufio.NewReader(conn)

	write("220 fake.smtp.local ESMTP")
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "HELO"):
			write("250 fake.smtp.local")
		case strings.HasPrefix(line, "MAIL FROM"):
			write("250 OK")
		case strings.HasPrefix(line, "RCPT TO"):
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

func TestEmail_Send_DialsConfiguredSMTPServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		fakeSMTPServer(conn)
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	e := NewEmail(EmailConfig{SMTPHost: host, SMTPPort: port, From: "radar@example.com", To: "oncall@example.com"})
	if err := e.Send(context.Background(), alert.Notification{Severity: "critical", Record: store.StoredRecord{ExpiryRecord: checker.ExpiryRecord{Source: "a", Name: "b"}}}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	<-done
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
