package logging

import (
	"testing"
	"unicode"
)

// FuzzSanitize: whatever external text reaches a log line, the result
// is one line, carries no control characters (log forging, terminal
// escapes), no character that hides or reorders text (bidi controls,
// zero-width characters) and no PEM block.
func FuzzSanitize(f *testing.F) {
	f.Add("ok")
	f.Add("a\nb\r\x1b[31mred")
	f.Add("-----BEGIN PRIVATE KEY-----\nMII\n-----END PRIVATE KEY-----")
	f.Add("password=hunter2 token: x")
	f.Add("line\u2028forged\u2029entry\u0085next")
	f.Add("user\u202egnp.exe\u2066x\u2069")
	f.Add("arabic\u061cmark zero\u200bwidth bom\ufeff")
	f.Fuzz(func(t *testing.T, s string) {
		out := Sanitize(s)
		for _, r := range out {
			if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' ||
				unicode.Is(unicode.Bidi_Control, r) || r == '\u200b' || r == '\ufeff' {
				t.Fatalf("unsafe rune %U survived in %q", r, out)
			}
		}
		if pemBlockRE.MatchString(out) {
			t.Fatalf("PEM block survived: %q", out)
		}
	})
}
