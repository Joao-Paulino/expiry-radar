//go:build !windows

package configperm

import (
	"os"
	"testing"
)

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
