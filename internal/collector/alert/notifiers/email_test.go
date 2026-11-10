package notifiers

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"strings"
	"testing"

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
