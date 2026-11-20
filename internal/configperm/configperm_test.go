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

func TestCheck_RejectsGroupAndOtherReadable(t *testing.T) {
	for _, mode := range []os.FileMode{0o604, 0o640, 0o644, 0o664, 0o666} {
		path := writeConfig(t, mode)
		if err := Check(path); err == nil {
			t.Fatalf("mode %o: want an error (holds secrets, must not be group/other readable)", mode)
		}
	}
}

func TestCheck_AcceptsOwnerOnly(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o400} {
		path := writeConfig(t, mode)
		if err := Check(path); err != nil {
			t.Fatalf("mode %o: want no error, got %v", mode, err)
		}
	}
}

func TestCheck_MissingFileIsIgnored(t *testing.T) {
	// Check is a permission guard, not existence validation; the
	// caller's own os.ReadFile reports a missing file.
	if err := Check(filepath.Join(t.TempDir(), "missing.json")); err != nil {
		t.Fatalf("want no error for a file this package didn't open, got %v", err)
	}
}
