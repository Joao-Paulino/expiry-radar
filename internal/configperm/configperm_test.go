package configperm

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("{}"), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil { // WriteFile's mode is masked by umask
		t.Fatal(err)
	}
	return path
}

func TestCheck_MissingFileIsIgnored(t *testing.T) {
	// Check is a permission guard, not existence validation; the
	// caller's own os.ReadFile reports a missing file. True on every
	// platform, Windows no-op included.
	if err := Check(filepath.Join(t.TempDir(), "missing.json")); err != nil {
		t.Fatalf("want no error for a file this package didn't open, got %v", err)
	}
}
