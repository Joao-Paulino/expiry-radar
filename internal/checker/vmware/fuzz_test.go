package vmware

import "testing"

// FuzzLeafOf: certificate chains come from vCenter's API; arbitrary
// strings must not panic.
func FuzzLeafOf(f *testing.F) {
	f.Add("-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = leafOf([]string{s, s})
	})
}
