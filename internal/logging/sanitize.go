// Package logging provides a secret-redacting sanitizer that every log
// line containing user- or external-supplied data must pass through
// first, so a stack trace or verbose log can never leak a secret.
package logging

import (
	"regexp"
	"strings"
	"unicode"
)

var pemBlockRE = regexp.MustCompile(`(?s)-----BEGIN [^-]+-----.*?-----END [^-]+-----`)

var keyValueRE = regexp.MustCompile(`(?i)(password|secret|token|apikey|api_key|access_key|private_key)\s*[:=]\s*\S+`)

// Sanitize scans s for substrings that look like secrets (PEM blocks,
// or key=value/key: value pairs whose key names a credential) and
// replaces them with redaction markers. It also escapes line breaks and
// other control characters, so external text can never forge a new log
// line or drive the terminal. Unicode line and paragraph separators
// (shown as line breaks by many viewers) and bidirectional formatting
// characters (which can make a line read differently from what it
// holds) are neutralised too.
func Sanitize(s string) string {
	s = pemBlockRE.ReplaceAllString(s, "[REDACTED-PEM]")
	s = keyValueRE.ReplaceAllString(s, "$1=[REDACTED]")
	if strings.IndexFunc(s, unsafeRune) < 0 {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case unsafeRune(r):
			b.WriteString("?")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func unsafeRune(r rune) bool {
	return unicode.IsControl(r) || r == '\u2028' || r == '\u2029' || isBidi(r)
}

// isBidi reports the Unicode bidirectional formatting characters
// (LRM, RLM, embeddings, overrides and isolates).
func isBidi(r rune) bool {
	return r == '\u200e' || r == '\u200f' || (r >= '\u202a' && r <= '\u202e') || (r >= '\u2066' && r <= '\u2069')
}
