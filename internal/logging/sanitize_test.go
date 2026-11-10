package logging

import (
	"strings"
	"testing"
)

func TestSanitize_KeyValuePairs(t *testing.T) {
	in := `connecting with password=supersecret123 and token: abc.def.ghi`
	out := Sanitize(in)
	if strings.Contains(out, "supersecret123") || strings.Contains(out, "abc.def.ghi") {
		t.Fatalf("secret leaked in output: %q", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Fatalf("expected redaction marker, got %q", out)
	}
}

func TestSanitize_PEMBlock(t *testing.T) {
	in := "cert:\n-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG\n-----END CERTIFICATE-----\ndone"
	out := Sanitize(in)
	if strings.Contains(out, "MIIBIjANBgkqhkiG") {
		t.Fatalf("PEM body leaked: %q", out)
	}
	if !strings.Contains(out, "[REDACTED-PEM]") {
		t.Fatalf("expected PEM redaction marker, got %q", out)
	}
}

func TestSanitize_NoSecrets(t *testing.T) {
	in := "checker tls-checker completed in 120ms"
	if out := Sanitize(in); out != in {
		t.Fatalf("expected unchanged string, got %q", out)
	}
}
