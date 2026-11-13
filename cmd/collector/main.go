// Command collector runs the Expiry Radar Collector: it serves the
// Agent-facing ingest endpoint, the dashboard, and periodically
// evaluates alert thresholds, notifying through configured channels.
//
// The actual wiring lives in internal/collector/server, so it can be
// started directly by tests (including the end-to-end test) without
// importing this non-importable main package.
package main

import (
	"context"
	"fmt"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/server"
	"github.com/Joao-Paulino/expiry-radar/internal/logging"
	"github.com/Joao-Paulino/expiry-radar/internal/service"
	"log"
	"os"
	"path/filepath"
	"time"
)

// Config is the collector binary's config type, loaded from a JSON
// file given as the binary's only CLI argument.
type Config = server.Config

func usage() {
	fmt.Fprintln(os.Stderr, "usage:\n  collector <config.json>\n  collector version\n  collector install-service <config.json> [--account NAME]\n  collector uninstall-service\n  collector set-admin-password <config.json>\n  collector set-admin-totp <config.json>")
	os.Exit(2)
}

func main() {
	if handleVersion(os.Args, os.Stdout) {
		return
	}
	if len(os.Args) < 2 {
		usage()
	}
	if handled, err := service.HandleCommand(os.Args, collectorService(), func(p string) error { _, err := loadConfig(p); return err }, os.Stdout); handled {
		if err != nil {
			fmt.Fprintf(os.Stderr, "collector: %s\n", err)
			os.Exit(1)
		}
		return
	}

	switch os.Args[1] {
	case "set-admin-password", "set-admin-totp":
		if len(os.Args) != 3 {
			usage()
		}
		var err error
		if os.Args[1] == "set-admin-password" {
			err = runSetAdminPassword(os.Args[2], os.Stdin, os.Stdout)
		} else {
			err = runSetAdminTOTP(os.Args[2], os.Stdin, os.Stdout, time.Now)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "collector: %s\n", err)
			os.Exit(1)
		}
		return
	}

	cfg, err := loadConfig(os.Args[1])
	if err != nil {
		log.Printf("collector: %s", logging.Sanitize(err.Error()))
		os.Exit(1)
	}

	if service.IsService() {
		// The SCM starts us in System32; relative paths in the config
		// are meant from the config file's folder.
		if err := os.Chdir(filepath.Dir(os.Args[1])); err != nil {
			log.Printf("collector: %s", logging.Sanitize(err.Error()))
			os.Exit(1)
		}
	}
	err = service.Run(collectorService().Name, func(ctx context.Context) error {
		cfg.Done = ctx.Done()
		return server.Run(cfg)
	})
	if err != nil {
		log.Printf("collector: %s", logging.Sanitize(err.Error()))
		os.Exit(1)
	}
}

// collectorService describes the collector's Windows service.
func collectorService() service.Spec {
	exe, _ := os.Executable()
	return service.Spec{Name: "ExpiryRadarCollector", DisplayName: "Expiry Radar Collector",
		Description: "Receives expiry reports from Expiry Radar agents, alerts and serves the dashboard.", Exe: exe}
}
