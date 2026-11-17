//go:build unix

package main

import (
	"os"
	"syscall"
)

// keepOwner gives f the owner and group of the file described by info,
// so a config rewritten as root stays readable by the service user.
func keepOwner(f *os.File, info os.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	return f.Chown(int(st.Uid), int(st.Gid))
}
