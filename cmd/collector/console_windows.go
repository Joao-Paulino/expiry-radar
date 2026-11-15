//go:build windows

package main

import (
	"io"
	"os"
	"strings"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

// The admin commands talk to the Windows console directly: echo is
// switched off with the console mode (no stty here), lines are read as
// UTF-16 so accented characters survive, and both code pages are set to
// UTF-8 so the prompts print correctly.
var (
	consoleReadLine = windowsReadLine
	consoleSetEcho  = windowsSetEcho
)

func init() {
	if platformIsTerminal(os.Stdout) {
		_ = windows.SetConsoleOutputCP(65001)
	}
	if platformIsTerminal(os.Stdin) {
		_ = windows.SetConsoleCP(65001)
	}
}

func consoleHandle(in io.Reader) (windows.Handle, bool) {
	f, ok := in.(*os.File)
	if !ok {
		return 0, false
	}
	h := windows.Handle(f.Fd())
	var mode uint32
	return h, windows.GetConsoleMode(h, &mode) == nil
}

func platformIsTerminal(in io.Reader) bool {
	_, ok := consoleHandle(in)
	return ok
}

func windowsSetEcho(in io.Reader, on bool) error {
	h, ok := consoleHandle(in)
	if !ok {
		return nil
	}
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return err
	}
	if on {
		mode |= windows.ENABLE_ECHO_INPUT
	} else {
		mode &^= windows.ENABLE_ECHO_INPUT
	}
	return windows.SetConsoleMode(h, mode)
}

// windowsReadLine reads one line with ReadConsoleW. ok is false when in
// is not a console, so the caller falls back to ordinary reads.
func windowsReadLine(in io.Reader) (string, bool, error) {
	h, ok := consoleHandle(in)
	if !ok {
		return "", false, nil
	}
	var out []uint16
	buf := make([]uint16, 256)
	for {
		var n uint32
		if err := windows.ReadConsole(h, &buf[0], uint32(len(buf)), &n, nil); err != nil {
			return "", true, err
		}
		if n == 0 {
			return "", true, io.EOF
		}
		out = append(out, buf[:n]...)
		if out[len(out)-1] == '\n' {
			break
		}
	}
	return strings.TrimRight(string(utf16.Decode(out)), "\r\n"), true, nil
}
