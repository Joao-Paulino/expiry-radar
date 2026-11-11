package main

import (
	"fmt"
	"io"
)

// version is set at release build time with
// -ldflags "-X main.version=<tag>".
var version = "dev"

// handleVersion prints the version and returns true when the first
// argument is "version" or "--version".
func handleVersion(args []string, out io.Writer) bool {
	if len(args) < 2 || (args[1] != "version" && args[1] != "--version") {
		return false
	}
	fmt.Fprintf(out, "expiry-radar agent %s\n", version)
	return true
}
