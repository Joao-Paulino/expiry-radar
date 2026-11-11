// Package dashboard serves the Collector's HTML dashboard: a list view
// with mute/assign-owner state, a per-record history view, and
// JSON/CSV export endpoints.
package dashboard

import (
	"embed"
	"html/template"
	"net/http"

	"github.com/Joao-Paulino/expiry-radar/internal/collector/export"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/rules"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/session"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/store"
)

//go:embed templates/*.html
var templatesFS embed.FS

var templates = template.Must(template.ParseFS(templatesFS, "templates/*.html"))

// recordView pairs a StoredRecord with its mute/owner rule state for
// rendering in the list view.
type recordView struct {
	Record store.StoredRecord
	Muted  bool
	Owner  string
}

// listView is the list page model: the records plus the CSRF token of
// the session viewing it (empty for bearer-token requests).
type listView struct {
	Records  []recordView
	Agents   []agentView
	Checkers []checkerView
	CSRF     string
}

// agentView is one agent and when it last pushed a batch.
type agentView struct {
	Agent, LastSeen string
}

// checkerView is one checker on one agent.
type checkerView struct {
	Agent, Checker, LastSeen, LastSuccess, LastError string
	Failures                                         int
}

// historyView holds the parameters and results of a history query for
// rendering in the history view.
type historyView struct {
	Source  string
	Name    string
	Kind    string
	Records []store.StoredRecord
}

// NewMux returns an http.ServeMux serving the Collector's dashboard.
func NewMux(st store.Store, rs rules.Store) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		records, err := st.ListCurrent(ctx)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		views := make([]recordView, 0, len(records))
		for _, rec := range records {
			view := recordView{Record: rec}
			rule, found, err := rs.Get(ctx, rec.Source, rec.Name, rec.Kind)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if found {
				view.Muted = rule.Muted
				view.Owner = rule.Owner
			}
			views = append(views, view)
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		health, err := st.CheckerHealth(ctx)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		seen, err := st.Agents(ctx)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		var agents []agentView
		for _, a := range seen {
			agents = append(agents, agentView{Agent: a.AgentID, LastSeen: a.LastSeenAt.UTC().Format("2006-01-02 15:04 UTC")})
		}
		var checkers []checkerView
		for _, h := range health {
			a := checkerView{Agent: h.ReportedBy, Checker: h.CheckerName, Failures: h.ConsecutiveFailures, LastError: h.LastError,
				LastSeen: h.LastSeenAt.UTC().Format("2006-01-02 15:04 UTC"), LastSuccess: "never"}
			if !h.LastSuccessAt.IsZero() {
				a.LastSuccess = h.LastSuccessAt.UTC().Format("2006-01-02 15:04 UTC")
			}
			checkers = append(checkers, a)
		}

		if err := templates.ExecuteTemplate(w, "list.html", listView{Records: views, Agents: agents, Checkers: checkers, CSRF: session.CSRFToken(ctx)}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	mux.HandleFunc("POST /agents/forget", func(w http.ResponseWriter, r *http.Request) {
		agentID := r.PostFormValue("agent_id")
		if agentID == "" {
			http.Error(w, "agent_id is required", http.StatusBadRequest)
			return
		}
		if err := st.ForgetAgent(r.Context(), agentID); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	mux.HandleFunc("GET /history", func(w http.ResponseWriter, r *http.Request) {
		source := r.URL.Query().Get("source")
		name := r.URL.Query().Get("name")
		kind := r.URL.Query().Get("kind")

		records, err := st.History(r.Context(), source, name, kind)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		view := historyView{Source: source, Name: name, Kind: kind, Records: records}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := templates.ExecuteTemplate(w, "history.html", view); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	mux.HandleFunc("POST /rules", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		rule := rules.Rule{
			Source: r.FormValue("source"),
			Name:   r.FormValue("name"),
			Kind:   r.FormValue("kind"),
			Muted:  r.FormValue("muted") == "on",
			Owner:  r.FormValue("owner"),
		}

		if err := rs.Upsert(r.Context(), rule); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	mux.HandleFunc("GET /export.json", func(w http.ResponseWriter, r *http.Request) {
		records, err := st.ListCurrent(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := export.JSON(w, records); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	mux.HandleFunc("GET /export.csv", func(w http.ResponseWriter, r *http.Request) {
		records, err := st.ListCurrent(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/csv")
		if err := export.CSV(w, records); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	return mux
}
