// Package service lets the collector and the agent run as a Windows
// service (installed with "install-service", controlled by the Service
// Control Manager, logging to the Event Log). Elsewhere, and from a
// console, Run simply runs until Ctrl+C or SIGTERM.
package service

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

// DefaultAccount is the least-privileged built-in service account.
const DefaultAccount = `NT AUTHORITY\LocalService`

// Spec describes a service to install.
type Spec struct {
	Name, DisplayName, Description string
	Exe                            string   // absolute path of the program
	Args                           []string // arguments after the program path
	Account                        string   // service account, DefaultAccount when empty
}

// ErrUnsupported is returned by Install and Uninstall outside Windows.
var ErrUnsupported = errors.New("services are installed this way only on Windows; on Linux use the systemd unit in the README")

// validateAccount accepts only accounts that need no password: the
// built-in service accounts and group managed service accounts (name$).
func validateAccount(a string) error {
	switch strings.ToLower(a) {
	case "", "localsystem", `nt authority\localservice`, `nt authority\networkservice`, `nt authority\system`:
		return nil
	}
	if strings.HasSuffix(a, "$") && strings.Contains(a, `\`) {
		return nil
	}
	return fmt.Errorf("account %q: use LocalSystem, NT AUTHORITY\\LocalService, NT AUTHORITY\\NetworkService or a gMSA (DOMAIN\\name$); accounts with a password are not supported", a)
}

// HandleCommand runs "install-service <config.json> [--account NAME]"
// and "uninstall-service" for a program whose service is base. check
// loads the config so a broken one is refused before installing. It
// reports whether args held one of these commands.
func HandleCommand(args []string, base Spec, check func(configPath string) error, out io.Writer) (bool, error) {
	if len(args) < 2 {
		return false, nil
	}
	switch args[1] {
	case "uninstall-service":
		if len(args) != 2 {
			return true, fmt.Errorf("usage: %s uninstall-service", filepath.Base(args[0]))
		}
		if err := Uninstall(base.Name); err != nil {
			return true, err
		}
		fmt.Fprintf(out, "Service %s removed.\n", base.Name)
		return true, nil
	case "install-service":
		usage := fmt.Errorf("usage: %s install-service <config.json> [--account NAME]", filepath.Base(args[0]))
		rest := args[2:]
		if len(rest) != 1 && !(len(rest) == 3 && rest[1] == "--account") {
			return true, usage
		}
		account := DefaultAccount
		if len(rest) == 3 {
			account = rest[2]
		}
		if err := validateAccount(account); err != nil {
			return true, err
		}
		cfg, err := filepath.Abs(rest[0])
		if err != nil {
			return true, err
		}
		if err := check(cfg); err != nil {
			return true, fmt.Errorf("config %s: %w", cfg, err)
		}
		spec := base
		spec.Args, spec.Account = []string{cfg}, account
		if err := Install(spec); err != nil {
			return true, err
		}
		fmt.Fprintf(out, "Service %s installed (account %s, automatic start, restarts on failure).\n", spec.Name, account)
		fmt.Fprintf(out, "Give the account access to the config folder, then start it:\n  icacls \"%s\" /grant \"%s:(OI)(CI)M\"\n  Start-Service %s\n", filepath.Dir(cfg), account, spec.Name)
		return true, nil
	}
	return false, nil
}
