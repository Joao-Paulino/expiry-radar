package dashboard

import (
	"fmt"
	"sort"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/collector/alert"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/store"
)

// Options configures how the dashboard renders.
type Options struct {
	// Theme is the default colour scheme: "auto" (follow the OS),
	// "dark" or "light". Each browser may override it.
	Theme string
}

func optionsOf(opts []Options) Options {
	if len(opts) == 0 {
		return Options{}
	}
	return opts[0]
}

func themeOrAuto(t string) string {
	if t == "dark" || t == "light" {
		return t
	}
	return "auto"
}

// summary counts the records per state for the cards on the list page.
type summary struct {
	Expired, Critical, Warning, OK int
}

// severityOf classifies a record for display, with the same thresholds
// alerts use: expired, critical, warning, ok, info (shown but never
// alerted) or unknown (no expiry date). days is whole days left
// (negative once expired); rel is a short human label.
func severityOf(r store.StoredRecord, now time.Time) (sev string, days int, rel string) {
	if r.ExpiresAt.IsZero() {
		return "unknown", 0, "—"
	}
	left := r.ExpiresAt.Sub(now)
	days = int(left.Hours() / 24)
	switch {
	case left < 0:
		rel = fmt.Sprintf("expired %d d ago", -days)
		if days == 0 {
			rel = "expired today"
		}
	case days == 0:
		rel = "today"
	default:
		rel = fmt.Sprintf("%d d", days)
	}
	switch {
	case r.Informational():
		sev = "info"
	case left < 0:
		sev = "expired"
	default:
		sev = string(alert.Evaluate(r, now, alert.DefaultThresholds()))
	}
	return sev, days, rel
}

// sortByExpiry orders soonest first; records without a date go last.
func sortByExpiry(v []recordView) {
	sort.SliceStable(v, func(i, j int) bool {
		a, b := v[i].Record.ExpiresAt, v[j].Record.ExpiresAt
		if a.IsZero() != b.IsZero() {
			return b.IsZero()
		}
		return a.Before(b)
	})
}

// uniqueSorted returns the distinct non-empty values, sorted.
func uniqueSorted(values []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range values {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
