//go:build unix

package main

import (
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// Rewriting the config must keep its owner: the installer gives it to
// the service user, and add-agent usually runs as root.
func TestAddAgent_KeepsOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to chown")
	}
	p := filepath.Join(t.TempDir(), "collector.json")
	os.WriteFile(p, []byte(`{"admin_tokens":["a"]}`), 0o640)
	if err := os.Chown(p, 4321, 4321); err != nil {
		t.Fatal(err)
	}
	if err := runAddAgent(p, "web-01", io.Discard); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(p)
	st := fi.Sys().(*syscall.Stat_t)
	if st.Uid != 4321 || st.Gid != 4321 {
		t.Fatalf("owner changed to %d:%d", st.Uid, st.Gid)
	}
}
