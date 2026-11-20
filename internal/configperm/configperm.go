// Package configperm checks that a config file holding secrets
// (collector/agent tokens, SMTP password, client secrets) is not
// readable by anyone other than its owner, the same way sshd refuses
// an overly permissive private key.
//
// On Windows this is a no-op (see configperm_windows.go): real ACL
// inspection needs the Windows security APIs, which we're not
// implementing without verifying the exact semantics against primary
// documentation first. Operators on Windows must rely on the NTFS
// ACLs the installer sets.
package configperm
