// Package checker defines the extension point for every expiry source
// Expiry Radar can monitor (TLS certificates, secrets, cloud resources,
// virtualization licenses) and the wire format used between the Agent
// and the Collector.
package checker

import (
	"context"
	"fmt"
	"time"
)

// ExpiryRecord describes one thing with an expiry date. It never
// carries the actual secret/private-key/credential value — only
// identifying metadata and the expiry date.
type ExpiryRecord struct {
	Source    string            `json:"source"`
	Name      string            `json:"name"`
	Kind      string            `json:"kind"`
	ExpiresAt time.Time         `json:"expires_at"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// Validate reports an error if the record is missing a required field.
func (r ExpiryRecord) Validate() error {
	if r.Source == "" {
		return fmt.Errorf("checker: ExpiryRecord.Source is required")
	}
	if r.Name == "" {
		return fmt.Errorf("checker: ExpiryRecord.Name is required")
	}
	if r.Kind == "" {
		return fmt.Errorf("checker: ExpiryRecord.Kind is required")
	}
	if r.ExpiresAt.IsZero() {
		return fmt.Errorf("checker: ExpiryRecord.ExpiresAt is required")
	}
	return nil
}

// Checker is the extension point every expiry source implements.
type Checker interface {
	// Name identifies this checker, e.g. "tls-checker" or "azure-cert-checker".
	Name() string
	// Kind classifies what this checker produces, e.g. "certificate",
	// "secret", "license", or "subscription".
	Kind() string
	// Check runs the checker once and returns the records it found.
	Check(ctx context.Context) ([]ExpiryRecord, error)
}

// Result is one Checker's outcome from a single run: either Records
// (success, possibly empty) or ErrMsg (non-empty), never both.
type Result struct {
	CheckerName string         `json:"checker_name"`
	Records     []ExpiryRecord `json:"records,omitempty"`
	ErrMsg      string         `json:"err_msg,omitempty"`
}

// Batch is what an Agent pushes to the Collector in one request.
type Batch struct {
	AgentID string   `json:"agent_id"`
	Results []Result `json:"results"`
}
