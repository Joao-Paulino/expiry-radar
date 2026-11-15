//go:build windows

package local

import (
	"context"
	"testing"
)

// The runner's LocalMachine\My may be empty; what matters is that the
// store opens and enumerates without error.
func TestStoreChecker(t *testing.T) {
	c := Checkers(&Config{})[0]
	if c.Name() != "windows-certstore" {
		t.Fatal(c.Name())
	}
	recs, err := c.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if r.Source != "certstore://LocalMachine/My" && r.Source != "certstore://LocalMachine/WebHosting" || r.Name == "" {
			t.Errorf("bad record %+v", r)
		}
	}
	// Root is readable too and is never empty.
	recs, err = (&storeChecker{stores: []string{"Root"}}).Check(context.Background())
	if err != nil || len(recs) == 0 {
		t.Fatalf("Root store: %d %v", len(recs), err)
	}
}
