//go:build windows

package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

// stopTimeout bounds how long Stop waits for fn to return.
const stopTimeout = 20 * time.Second

// IsService reports whether the Service Control Manager started us.
func IsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

// Run calls fn. Under the Service Control Manager it reports the service
// state, cancels ctx on Stop or Shutdown and sends log output to the
// Event Log; from a console, ctx is cancelled on Ctrl+C.
func Run(name string, fn func(ctx context.Context) error) error {
	if !IsService() {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		return fn(ctx)
	}
	if el, err := eventlog.Open(name); err == nil {
		defer el.Close()
		log.SetFlags(0)
		log.SetOutput(eventWriter{el})
	}
	h := &handler{fn: fn}
	if err := svc.Run(name, h); err != nil {
		return err
	}
	return h.err
}

type handler struct {
	fn  func(ctx context.Context) error
	err error
}

func (h *handler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.fn(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	log.Printf("started")
	for {
		select {
		case err := <-done:
			// Stopped on its own: an error makes the SCM apply the
			// recovery actions (restart).
			if err != nil {
				h.err = err
				log.Printf("stopped: %v", err)
				return true, 1
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending, WaitHint: uint32(stopTimeout / time.Millisecond)}
				cancel()
				select {
				case <-done:
				case <-time.After(stopTimeout):
				}
				log.Printf("stopped")
				return false, 0
			}
		}
	}
}

// eventWriter sends each log line to the Event Log, as an error when it
// reads like one.
type eventWriter struct{ el *eventlog.Log }

func (w eventWriter) Write(p []byte) (int, error) {
	msg := strings.TrimRight(string(p), "\r\n")
	lower := strings.ToLower(msg)
	var err error
	if strings.Contains(lower, "error") || strings.Contains(lower, "fail") {
		err = w.el.Error(1, msg)
	} else {
		err = w.el.Info(1, msg)
	}
	return len(p), err
}

// Install registers the service: automatic start, restart after one
// minute on failure (three times, counter reset after a day), and an
// Event Log source with the same name.
func Install(s Spec) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connecting to the Service Control Manager (run as Administrator): %w", err)
	}
	defer m.Disconnect()
	if old, err := m.OpenService(s.Name); err == nil {
		old.Close()
		return fmt.Errorf("service %s already exists; run uninstall-service first", s.Name)
	}
	account := s.Account
	if account == "" {
		account = DefaultAccount
	}
	if strings.EqualFold(account, "LocalSystem") {
		account = "" // the SCM's spelling of LocalSystem
	}
	created, err := m.CreateService(s.Name, s.Exe, mgr.Config{
		DisplayName: s.DisplayName, Description: s.Description,
		StartType: mgr.StartAutomatic, ServiceStartName: account,
	}, s.Args...)
	if err != nil {
		return fmt.Errorf("creating service %s: %w", s.Name, err)
	}
	defer created.Close()
	restart := mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: time.Minute}
	if err := created.SetRecoveryActions([]mgr.RecoveryAction{restart, restart, restart}, 24*60*60); err != nil {
		return fmt.Errorf("setting recovery actions: %w", err)
	}
	if err := created.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return fmt.Errorf("setting recovery actions: %w", err)
	}
	if err := eventlog.InstallAsEventCreate(s.Name, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil &&
		!strings.Contains(err.Error(), "registry key already exists") {
		return fmt.Errorf("registering Event Log source: %w", err)
	}
	return nil
}

// Uninstall stops the service if it runs, deletes it and removes its
// Event Log source.
func Uninstall(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connecting to the Service Control Manager (run as Administrator): %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("service %s is not installed", name)
	}
	defer s.Close()
	if st, err := s.Control(svc.Stop); err == nil {
		for deadline := time.Now().Add(stopTimeout); st.State != svc.Stopped && time.Now().Before(deadline); {
			time.Sleep(300 * time.Millisecond)
			if st, err = s.Query(); err != nil {
				break
			}
		}
	} else if !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		return fmt.Errorf("stopping %s: %w", name, err)
	}
	if err := s.Delete(); err != nil {
		return fmt.Errorf("deleting %s: %w", name, err)
	}
	_ = eventlog.Remove(name)
	return nil
}
