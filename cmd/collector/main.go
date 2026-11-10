// Command collector runs the Expiry Radar Collector: it serves the
// Agent-facing ingest endpoint, the dashboard, and periodically
// evaluates alert thresholds, notifying through configured channels.
//
// The actual wiring lives in internal/collector/server, so it can be
// started directly by tests (including the end-to-end test) without
// importing this non-importable main package.
package main

import (
	"encoding/json"
	"log"
	"os"

	"github.com/Joao-Paulino/expiry-radar/internal/collector/server"
	"github.com/Joao-Paulino/expiry-radar/internal/logging"
)

// Config is the collector binary's config type, loaded from a JSON
// file given as the binary's only CLI argument.
type Config = server.Config

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: collector <config.json>")
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		log.Printf("collector: reading config: %s", logging.Sanitize(err.Error()))
		os.Exit(1)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Printf("collector: parsing config: %s", logging.Sanitize(err.Error()))
		os.Exit(1)
	}

	if err := server.Run(cfg); err != nil {
		log.Printf("collector: %s", logging.Sanitize(err.Error()))
		os.Exit(1)
	}
}
