package azure

import (
	"encoding/base64"
	"strings"
	"testing"
)

// FuzzLeafFromPublicCertData: App Gateway's publicCertData is parsed
// with hand-written PKCS#7 ASN.1 structures; arbitrary input must not
// panic.
func FuzzLeafFromPublicCertData(f *testing.F) {
	f.Add(base64.StdEncoding.EncodeToString([]byte{0x30, 0x03, 0x06, 0x01, 0x00}))
	f.Add("MIIB")
	f.Add("")
	f.Add(base64.StdEncoding.EncodeToString([]byte("-----BEGIN PKCS7-----\nMAA=\n-----END PKCS7-----\n")))
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = leafFromPublicCertData(s)
		_, _ = leafFromPublicCertData(base64.StdEncoding.EncodeToString([]byte(s)))
	})
}

// FuzzSafeResourceID: whatever ID ARM returns, an accepted one stays
// inside the subscription's resource groups and cannot change host,
// query or path depth.
func FuzzSafeResourceID(f *testing.F) {
	sub := "00000000-0000-0000-0000-000000000000"
	f.Add("/subscriptions/" + sub + "/resourceGroups/rg/providers/Microsoft.Web/certificates/c")
	f.Add("/subscriptions/" + sub + "/resourceGroups/../../x")
	f.Add("/subscriptions/" + sub + "/resourceGroups/rg/x?api-version=1")
	f.Add("//evil.example/subscriptions/" + sub + "/resourceGroups/")
	f.Fuzz(func(t *testing.T, id string) {
		if !safeResourceID(id, sub) {
			return
		}
		lower := strings.ToLower(id)
		if !strings.HasPrefix(lower, "/subscriptions/"+sub+"/resourcegroups/") {
			t.Fatalf("accepted outside subscription: %q", id)
		}
		for _, bad := range []string{"..", "//", "?", "#", "%", "@", "\\", " ", "\n", "\r", "\t"} {
			if strings.Contains(id, bad) {
				t.Fatalf("accepted %q containing %q", id, bad)
			}
		}
	})
}
