//go:build windows

package service

import (
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// TestInstallUninstall registers a real service (not started) and
// checks its configuration. It needs an elevated prompt, as on CI.
func TestInstallUninstall(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs Administrator")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	name := "ExpiryRadarTest" + time.Now().Format("150405")
	spec := Spec{Name: name, DisplayName: "Expiry Radar test", Description: "test", Exe: exe, Args: []string{`C:\some dir\config.json`}}
	if err := Install(spec); err != nil {
		t.Fatal(err)
	}
	defer Uninstall(name)
	if err := Install(spec); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("second install: %v", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := s.Config()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.StartType != mgr.StartAutomatic || !strings.EqualFold(cfg.ServiceStartName, DefaultAccount) ||
		!strings.Contains(cfg.BinaryPathName, `"C:\some dir\config.json"`) {
		t.Errorf("config: %+v", cfg)
	}
	actions, err := s.RecoveryActions()
	if err != nil || len(actions) != 3 || actions[0].Type != mgr.ServiceRestart || actions[0].Delay != time.Minute {
		t.Errorf("recovery: %+v %v", actions, err)
	}
	s.Close()

	if err := Uninstall(name); err != nil {
		t.Fatal(err)
	}
	if err := Uninstall(name); err == nil {
		t.Error("uninstalling twice should fail")
	}
}
