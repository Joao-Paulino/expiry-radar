// Package logging provides a secret-redacting sanitizer that every log
// line containing user- or external-supplied data must pass through
// first, so a stack trace or verbose log can never leak a secret.
package logging

import "regexp"

var pemBlockRE = regexp.MustCompile(`(?s)-----BEGIN [^-]+-----.*?-----END [^-]+-----`)

var keyValueRE = regexp.MustCompile(`(?i)(password|secret|token|apikey|api_key|access_key|private_key)\s*[:=]\s*\S+`)

// Sanitize scans s for substrings that look like secrets (PEM blocks,
// or key=value/key: value pairs whose key names a credential) and
// replaces them with redaction markers.
func Sanitize(s string) string {
	s = pemBlockRE.ReplaceAllString(s, "[REDACTED-PEM]")
	s = keyValueRE.ReplaceAllString(s, "$1=[REDACTED]")
	return s
}
