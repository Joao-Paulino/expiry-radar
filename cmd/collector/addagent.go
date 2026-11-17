package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

// agentIDPattern keeps agent IDs printable and safe in logs, URLs and
// file names.
var agentIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// runAddAgent adds a per-agent token to the collector config at path
// and prints it once. The token may only report as agentID. Other keys
// in the file are kept; the file's permissions are kept; the write is
// atomic (temporary file + rename).
func runAddAgent(path, agentID string, out io.Writer) error {
	if !agentIDPattern.MatchString(agentID) {
		return errors.New("agent id: 1 to 64 characters, letters, digits, '.', '_' or '-', starting with a letter or digit")
	}
	data, err := os.ReadFile(path) // #nosec G304 -- operator's own config file
	if err != nil {
		return err
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}
	agents, _ := cfg["agents"].([]any)
	for _, a := range agents {
		if m, ok := a.(map[string]any); ok && m["id"] == agentID {
			return fmt.Errorf("agent %q already exists; remove it from %s to issue a new token", agentID, path)
		}
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return err
	}
	token := hex.EncodeToString(buf)
	cfg["agents"] = append(agents, map[string]any{"id": agentID, "token": token})
	updated, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".collector-*.json")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(append(updated, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := keepOwner(tmp, info); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	fmt.Fprintf(out, "Agent %q added. Its token (shown once; put it in that agent's agent.json as \"token\", with \"agent_id\": %q):\n\n  %s\n\n", agentID, agentID, token)
	fmt.Fprintln(out, "Restart the collector to load it. This token can only report as this agent.")
	return nil
}
