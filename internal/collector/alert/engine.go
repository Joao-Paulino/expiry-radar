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

// Notification pairs a StoredRecord with its computed Severity and
// whether a mute rule applies to it.
type Notification struct {
	Record   store.StoredRecord
	Severity Severity
	Muted    bool
}

// Engine evaluates every current record against Thresholds and Rules.
type Engine struct {
	Store      store.Store
	Rules      rules.Store
	Thresholds Thresholds
	StaleAfter time.Duration
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

		notifications = append(notifications, Notification{
			Record:   record,
			Severity: Evaluate(record, now, e.Thresholds),
			Muted:    found && rule.Muted,
		})
	}

	return notifications, nil
}
