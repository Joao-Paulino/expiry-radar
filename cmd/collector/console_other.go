//go:build !windows

package main

import (
	"io"
	"os"
)

// Console hooks used by admin_cmd.go; only Windows sets them.
var (
	consoleReadLine func(in io.Reader) (line string, ok bool, err error)
	consoleSetEcho  func(in io.Reader, on bool) error
)

func platformIsTerminal(in io.Reader) bool {
	f, ok := in.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
