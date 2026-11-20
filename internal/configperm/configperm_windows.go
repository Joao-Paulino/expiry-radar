//go:build windows

package configperm

// Check is a no-op on Windows: os.FileInfo.Mode() does not reflect
// NTFS ACLs, and we're not implementing ACL inspection without first
// verifying the Windows security APIs against primary documentation.
// Operators must rely on the ACLs the installer/service setup sets.
func Check(path string) error { return nil }
