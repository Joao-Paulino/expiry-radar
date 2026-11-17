package logging

import (
	"testing"
	"unicode"
)

// FuzzSanitize: whatever external text reaches a log line, the result
// is one line, carries no control characters (log forging, terminal
// escapes) and no PEM block.
func FuzzSanitize(f *testing.F) {
	f.Add("ok")
	f.Add("a\nb\r\x1b[31mred")
	f.Add("-----BEGIN PRIVATE KEY-----\nMII\n-----END PRIVATE KEY-----")
	f.Add("password=hunter2 token: x")
	f.Add("line forged entry\u0085next")
	f.Fuzz(func(t *testing.T, s string) {
		out := Sanitize(s)
		for _, r := range out {
			if unicode.IsControl(r) || r == ' ' || r == ' ' {
				t.Fatalf("control or line separator %U survived in %q", r, out)
			}
		}
		if pemBlockRE.MatchString(out) {
			t.Fatalf("PEM block survived: %q", out)
		}
	})
}
