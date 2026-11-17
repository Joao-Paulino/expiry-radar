//go:build !unix

package main

import "os"

// keepOwner is a no-op outside Unix: on Windows the rewritten file takes
// the folder's ACL, and the installer re-applies the file's own ACL.
func keepOwner(*os.File, os.FileInfo) error { return nil }
