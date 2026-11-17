package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAddAgent(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "collector.json")
	orig := `{"db_path":"r.db","listen_addr":"0.0.0.0:8443","theme":"dark","auth_tokens":[],"admin_tokens":["a"]}`
	if err := os.WriteFile(p, []byte("\xef\xbb\xbf"+orig), 0o640); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runAddAgent(p, "web-01", &out); err != nil {
		t.Fatal(err)
	}
	if err := runAddAgent(p, "db-01", &out); err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	data, _ := os.ReadFile(p)
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("config no longer valid JSON: %v", err)
	}
	agents, _ := cfg["agents"].([]any)
	if len(agents) != 2 || cfg["theme"] != "dark" || cfg["db_path"] != "r.db" {
		t.Fatalf("agents not added or other keys lost: %v", cfg)
	}
	tok := agents[0].(map[string]any)["token"].(string)
	if len(tok) < 32 || !strings.Contains(out.String(), tok) {
		t.Fatalf("token not generated or not shown once: %q", tok)
	}
	if tok == agents[1].(map[string]any)["token"].(string) {
		t.Fatal("two agents got the same token")
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o640 {
		t.Errorf("file mode changed to %v", fi.Mode().Perm())
	}
	if err := runAddAgent(p, "web-01", &out); err == nil {
		t.Error("duplicate agent id accepted")
	}
	for _, bad := range []string{"", "a b", "x/y", strings.Repeat("a", 65)} {
		if err := runAddAgent(p, bad, &out); err == nil {
			t.Errorf("agent id %q accepted", bad)
		}
	}
}
