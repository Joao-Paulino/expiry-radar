//go:build !windows

package service

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// IsService reports whether the Service Control Manager started us.
func IsService() bool { return false }

// Run calls fn with a context cancelled on Ctrl+C or SIGTERM.
func Run(name string, fn func(ctx context.Context) error) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return fn(ctx)
}

// Install is only available on Windows.
func Install(Spec) error { return ErrUnsupported }

// Uninstall is only available on Windows.
func Uninstall(string) error { return ErrUnsupported }
