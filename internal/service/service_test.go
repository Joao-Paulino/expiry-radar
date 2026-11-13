package service

import (
	"errors"
	"io"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestValidateAccount(t *testing.T) {
	for _, ok := range []string{"", "LocalSystem", `NT AUTHORITY\LocalService`, `nt authority\networkservice`, `CORP\expiry-radar$`} {
		if err := validateAccount(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{`CORP\bob`, "bob", "Administrator", "radar$"} {
		if validateAccount(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestHandleCommand(t *testing.T) {
	base := Spec{Name: "ExpiryRadarTest"}
	okCheck := func(string) error { return nil }

	if handled, _ := HandleCommand([]string{"x", "config.json"}, base, okCheck, io.Discard); handled {
		t.Error("a config path is not a service command")
	}
	if handled, _ := HandleCommand([]string{"x"}, base, okCheck, io.Discard); handled {
		t.Error("no arguments is not a service command")
	}
	for _, args := range [][]string{
		{"x", "install-service"},
		{"x", "install-service", "a.json", "--account"},
		{"x", "install-service", "a.json", "--user", "LocalSystem"},
		{"x", "uninstall-service", "extra"},
	} {
		if handled, err := HandleCommand(args, base, okCheck, io.Discard); !handled || err == nil || !strings.Contains(err.Error(), "usage") {
			t.Errorf("%v: handled=%v err=%v, want a usage error", args, handled, err)
		}
	}

	// A password account is refused before the config is even read.
	called := false
	_, err := HandleCommand([]string{"x", "install-service", "a.json", "--account", `CORP\bob`}, base, func(string) error { called = true; return nil }, io.Discard)
	if err == nil || called {
		t.Errorf("password account: err=%v check called=%v", err, called)
	}

	// A broken config is refused, and the check sees an absolute path.
	var seen string
	_, err = HandleCommand([]string{"x", "install-service", "a.json"}, base, func(p string) error { seen = p; return errors.New("bad json") }, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "bad json") || !filepath.IsAbs(seen) {
		t.Errorf("broken config: err=%v path=%q", err, seen)
	}

	if runtime.GOOS != "windows" {
		if _, err := HandleCommand([]string{"x", "install-service", "a.json"}, base, okCheck, io.Discard); !errors.Is(err, ErrUnsupported) {
			t.Errorf("install outside Windows: %v", err)
		}
		if _, err := HandleCommand([]string{"x", "uninstall-service"}, base, okCheck, io.Discard); !errors.Is(err, ErrUnsupported) {
			t.Errorf("uninstall outside Windows: %v", err)
		}
	}
}
