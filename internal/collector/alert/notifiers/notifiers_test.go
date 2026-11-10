package notifiers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/alert"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/store"
)

type notifierFunc func(context.Context, alert.Notification) error

func (f notifierFunc) Send(ctx context.Context, n alert.Notification) error { return f(ctx, n) }

func TestSendAll_OneFailureDoesNotStopOthers(t *testing.T) {
	var secondCalled bool
	failing := notifierFunc(func(ctx context.Context, n alert.Notification) error { return errors.New("boom") })
	succeeding := notifierFunc(func(ctx context.Context, n alert.Notification) error { secondCalled = true; return nil })

	errs := SendAll(context.Background(), []Notifier{failing, succeeding}, alert.Notification{})
	if !secondCalled {
		t.Fatal("expected the second notifier to still be called")
	}
	if len(errs) != 1 {
		t.Fatalf("expected exactly 1 error, got %d", len(errs))
	}
}

func TestWebhook_Send_PostsJSON(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	wh := NewWebhook(srv.URL)
	n := alert.Notification{Severity: "critical", Record: store.StoredRecord{ExpiryRecord: checker.ExpiryRecord{Source: "a", Name: "b"}}}
	if err := wh.Send(context.Background(), n); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotBody["severity"] != "critical" {
		t.Fatalf("got body %+v", gotBody)
	}
}
