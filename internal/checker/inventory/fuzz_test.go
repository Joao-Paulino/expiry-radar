package inventory

import "testing"

// Inventory files are edited by hand: no input may panic the parser.
func FuzzParse(f *testing.F) {
	f.Add([]byte("name,expires_at\nx,2027-01-01\n"), true)
	f.Add([]byte(`[{"name":"x","expires_at":"2027-01-01"}]`), false)
	f.Fuzz(func(t *testing.T, b []byte, csv bool) {
		if csv {
			_, _ = parseCSV("f.csv", b)
		} else {
			_, _ = parseJSON("f.json", b)
		}
	})
}
