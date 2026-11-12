// Package alert evaluates stored ExpiryRecords against configurable
// per-kind thresholds and mute/owner rules to produce notifications.
package alert

import (
	"context"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/collector/rules"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/store"
)

// Severity is how urgently a record needs attention.
type Severity string

const (
	SeverityOK       Severity = "ok"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
	SeverityUnknown  Severity = "unknown"
)

// Threshold is the warn/critical boundary, in days remaining, for one Kind.
type Threshold struct {
	WarnDays int
	CritDays int
}

// Thresholds maps a Kind to its Threshold.
type Thresholds map[string]Threshold

const (
	defaultWarnDays = 30
	defaultCritDays = 7
)

var defaultThreshold = Threshold{WarnDays: defaultWarnDays, CritDays: defaultCritDays}

// DefaultThresholds returns every known Kind ("certificate", "secret",
// "license", "subscription") mapped to the default warn-at-30-days,
// critical-at-7-days threshold. A Kind not present here still falls
// back to the same default in Evaluate.
func DefaultThresholds() Thresholds {
	return Thresholds{
		"certificate":  defaultThreshold,
		"secret":       defaultThreshold,
		"license":      defaultThreshold,
		"subscription": defaultThreshold,
	}
}

// Evaluate returns the Severity of record at the given time, under
// thresholds (falling back to the default warn/critical days for any
// Kind not present in thresholds).
func Evaluate(record store.StoredRecord, now time.Time, thresholds Thresholds) Severity {
	th, ok := thresholds[record.Kind]
	if !ok {
		th = defaultThreshold
	}

	daysRemaining := int(record.ExpiresAt.Sub(now).Hours() / 24)

	switch {
	case daysRemaining <= th.CritDays:
		return SeverityCritical
	case daysRemaining <= th.WarnDays:
		return SeverityWarning
	default:
		return SeverityOK
	}
}

// Type is what a Notification is about.
type Type string

const (
	TypeExpiry        Type = "expiry"         // a record nears or passed expiry
	TypeCheckerFailed Type = "checker_failed" // a checker keeps failing on an agent
	TypeAgentSilent   Type = "agent_silent"   // an agent stopped reporting
)

// Notification is one evaluated alert subject. For TypeExpiry, Record
// is set; for health types, Agent (and Checker) are.
type Notification struct {
	Type     Type
	Record   store.StoredRecord
	Agent    string
	Checker  string
	Detail   string // last checker error, for TypeCheckerFailed
	Severity Severity
	Muted    bool
	Resolved bool // set by the sender when this reports a return to OK
	// Gone: the item is no longer reported (deleted, renamed, rotated
	// away). Its ExpiresAt is unknown (zero).
	Gone bool
}

// Key identifies the alert subject for deduplication.
func (n Notification) Key() string {
	switch n.Type {
	case TypeCheckerFailed:
		return "checker|" + n.Agent + "|" + n.Checker
	case TypeAgentSilent:
		return "agent|" + n.Agent
	default:
		return "expiry|" + n.Record.Source + "|" + n.Record.Name + "|" + n.Record.Kind
	}
}

const (
	defaultFailThreshold = 3
	defaultStaleAfter    = 3 * time.Hour
)

// Engine evaluates every current record against Thresholds and Rules.
type Engine struct {
	Store      store.Store
	Rules      rules.Store
	Thresholds Thresholds
	// FailThreshold is how many consecutive failures make a checker
	// alert (default 3); StaleAfter is how long an agent may stay
	// silent before it alerts (default 3h).
	FailThreshold int
	StaleAfter    time.Duration
}

// Evaluate returns one Notification per current record, with muted
// records included (marked Muted: true) rather than filtered out —
// filtering for delivery happens at the notifier step.
func (e *Engine) Evaluate(ctx context.Context, now time.Time) ([]Notification, error) {
	records, err := e.Store.ListCurrent(ctx)
	if err != nil {
		return nil, err
	}

	var notifications []Notification
	for _, record := range records {
		rule, found, err := e.Rules.Get(ctx, record.Source, record.Name, record.Kind)
		if err != nil {
			return nil, err
		}

		sev := Evaluate(record, now, e.Thresholds)
		// Informational records (a checker sets alerts=off, e.g. an
		// inactive access key) are shown on the dashboard, never alerted.
		if record.Informational() {
			sev = SeverityOK
		}
		notifications = append(notifications, Notification{
			Type:     TypeExpiry,
			Record:   record,
			Severity: sev,
			Muted:    found && rule.Muted,
		})
	}

	health, err := e.Store.CheckerHealth(ctx)
	if err != nil {
		return nil, err
	}
	failThreshold, staleAfter := e.FailThreshold, e.StaleAfter
	if failThreshold <= 0 {
		failThreshold = defaultFailThreshold
	}
	if staleAfter <= 0 {
		staleAfter = defaultStaleAfter
	}

	for _, h := range health {
		sev := SeverityOK
		if h.ConsecutiveFailures >= failThreshold {
			sev = SeverityCritical
		}
		notifications = append(notifications, Notification{
			Type: TypeCheckerFailed, Agent: h.ReportedBy, Checker: h.CheckerName, Detail: h.LastError, Severity: sev,
		})
	}

	// Silence is judged on the last batch from each agent, so an agent
	// that reports with no checker results still counts as alive.
	agents, err := e.Store.Agents(ctx)
	if err != nil {
		return nil, err
	}
	for _, a := range agents {
		sev := SeverityOK
		if now.Sub(a.LastSeenAt) > staleAfter {
			sev = SeverityCritical
		}
		notifications = append(notifications, Notification{Type: TypeAgentSilent, Agent: a.AgentID, Severity: sev})
	}

	return notifications, nil
}
