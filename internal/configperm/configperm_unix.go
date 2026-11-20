//go:build !windows

package configperm

import (
	"fmt"
	"os"
)

// Check refuses a config file that any other user on the machine
// could read or write: the group and "other" permission bits must
// both be zero. A missing file is not this package's concern - the
// caller's own read reports that.
func Check(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("configperm: %s: %w", path, err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("configperm: %s has mode %04o, readable or writable by group/other; it holds secrets - run: chmod 600 %s", path, perm, path)
	}
	return nil
}
