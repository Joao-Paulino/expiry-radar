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
		if err := templates.ExecuteTemplate(w, "list.html", views); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
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
