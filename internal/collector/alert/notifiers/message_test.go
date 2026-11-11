package notifiers

import (
	"strings"
	"testing"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/alert"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/store"
)

func TestMessageFor_ByType(t *testing.T) {
	exp := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	cases := map[string]struct {
		n    alert.Notification
		want []string
	}{
		"expiry": {alert.Notification{Type: alert.TypeExpiry, Severity: alert.SeverityCritical,
			Record: store.StoredRecord{ExpiryRecord: checker.ExpiryRecord{Source: "a:443", Name: "a", Kind: "certificate", ExpiresAt: exp}}},
			[]string{"[critical]", "a:443/a", "2026-12-01"}},
		"expiry resolved": {alert.Notification{Type: alert.TypeExpiry, Resolved: true, Severity: alert.SeverityOK,
			Record: store.StoredRecord{ExpiryRecord: checker.ExpiryRecord{Source: "a:443", Name: "a", Kind: "certificate", ExpiresAt: exp}}},
			[]string{"[resolved]", "a:443/a"}},
		"checker failed": {alert.Notification{Type: alert.TypeCheckerFailed, Severity: alert.SeverityCritical, Agent: "web-01", Checker: "tls", Detail: "timeout"},
			[]string{"[critical]", "checker tls", "web-01", "timeout"}},
		"agent silent": {alert.Notification{Type: alert.TypeAgentSilent, Severity: alert.SeverityCritical, Agent: "web-03"},
			[]string{"[critical]", "agent web-03", "stopped reporting"}},
		"agent back": {alert.Notification{Type: alert.TypeAgentSilent, Resolved: true, Agent: "web-03"},
			[]string{"[resolved]", "agent web-03"}},
	}
	for name, c := range cases {
		msg := messageFor(c.n)
		for _, w := range c.want {
			if !strings.Contains(msg, w) {
				t.Errorf("%s: %q does not contain %q", name, msg, w)
			}
		}
	}
}

func TestPayloadFor_IncludesTypeAndResolved(t *testing.T) {
	p := payloadFor(alert.Notification{Type: alert.TypeCheckerFailed, Resolved: true, Agent: "web-01", Checker: "tls", Detail: "x"})
	if p.Type != "checker_failed" || !p.Resolved || p.Agent != "web-01" || p.Checker != "tls" || p.Detail != "x" {
		t.Fatalf("got %+v", p)
	}
}

func TestEmailSubject_ByType(t *testing.T) {
	if s := subjectFor(alert.Notification{Type: alert.TypeAgentSilent, Agent: "web-03\r\nBcc: x"}); !strings.Contains(s, "web-03") || strings.ContainsAny(s, "\r\n") {
		t.Fatalf("got %q", s)
	}
}
