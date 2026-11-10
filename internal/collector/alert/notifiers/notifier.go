// Package notifiers sends alert notifications through configured
// channels (webhook, Slack, Teams, email).
package notifiers

import (
	"context"

	"github.com/Joao-Paulino/expiry-radar/internal/collector/alert"
)

// Notifier delivers one Notification through a channel.
type Notifier interface {
	Send(ctx context.Context, n alert.Notification) error
}

// SendAll calls Send on every notifier for n, never letting one
// notifier's failure stop the others. It returns the errors from any
// notifiers that failed, in the order they were given.
func SendAll(ctx context.Context, ns []Notifier, n alert.Notification) []error {
	var errs []error
	for _, notifier := range ns {
		if err := notifier.Send(ctx, n); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}
