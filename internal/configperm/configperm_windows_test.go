//go:build windows

package configperm

import "testing"

// On Windows, Check is a documented no-op: os.FileInfo.Mode() doesn't
// reflect NTFS ACLs, so even a loosely-permissioned file must not
// error here.
func TestCheck_IsNoOp(t *testing.T) {
	path := writeConfig(t, 0o666)
	if err := Check(path); err != nil {
		t.Fatalf("want no error on Windows (no-op), got %v", err)
	}
}
