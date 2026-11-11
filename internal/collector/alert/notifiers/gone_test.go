package notifiers

import (
	"strings"
	"testing"

	"github.com/Joao-Paulino/expiry-radar/internal/collector/alert"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/store"
)

// A gone item must not read like a renewal: if it vanished by mistake,
// the reader has to check.
func TestMessageFor_GoneItem(t *testing.T) {
	var r store.StoredRecord
	r.Source, r.Name, r.Kind = "azure://kv.vault.azure.net", "db-pass", "secret"
	msg := messageFor(alert.Notification{Type: alert.TypeExpiry, Record: r, Severity: alert.SeverityOK, Resolved: true, Gone: true})
	if strings.Contains(msg, "no longer near expiry") || strings.Contains(msg, "0001") || !strings.Contains(msg, "no longer reported") {
		t.Fatalf("message: %q", msg)
	}
}
