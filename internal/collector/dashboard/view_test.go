package dashboard

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Joao-Paulino/expiry-radar/internal/checker"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/rules"
	"github.com/Joao-Paulino/expiry-radar/internal/collector/store"
)

func rec(name, kind string, exp time.Time, md map[string]string) store.StoredRecord {
	return store.StoredRecord{ExpiryRecord: checker.ExpiryRecord{Source: "src", Name: name, Kind: kind, ExpiresAt: exp, Metadata: md}}
}

func TestSeverity(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	off := map[string]string{"alerts": "off"}
	cases := []struct {
		r        store.StoredRecord
		sev, rel string
	}{
		{rec("a", "certificate", now.Add(-2*24*time.Hour-time.Hour), nil), "expired", "expired 2 d ago"},
		{rec("a", "certificate", now.Add(3*24*time.Hour+time.Hour), nil), "critical", "3 d"},
		{rec("a", "certificate", now.Add(20*24*time.Hour+time.Hour), nil), "warning", "20 d"},
		{rec("a", "certificate", now.Add(90*24*time.Hour+time.Hour), nil), "ok", "90 d"},
		{rec("a", "access_key", now.Add(3*24*time.Hour), off), "info", "3 d"},
		{rec("a", "certificate", now.Add(5*time.Hour), nil), "critical", "today"},
		{rec("a", "certificate", time.Time{}, nil), "unknown", "—"},
	}
	for i, c := range cases {
		sev, _, rel := severityOf(c.r, now)
		if sev != c.sev || rel != c.rel {
			t.Errorf("case %d: got %q %q, want %q %q", i, sev, rel, c.sev, c.rel)
		}
	}
}

func TestMux_List_SummaryAndTheme(t *testing.T) {
	now := time.Now()
	st := &fakeStore{current: []store.StoredRecord{
		rec("e", "certificate", now.Add(-48*time.Hour), nil),
		rec("c", "certificate", now.Add(72*time.Hour), nil),
		rec("w", "secret", now.Add(20*24*time.Hour), nil),
		rec("o", "secret", now.Add(200*24*time.Hour), nil),
		rec("o2", "secret", now.Add(300*24*time.Hour), nil),
	}}
	body := get(t, NewMux(st, &fakeRulesStore{}, Options{Theme: "dark"}), "/")
	if !strings.Contains(body, `data-theme="dark"`) {
		t.Fatal("theme not rendered")
	}
	for _, want := range []string{`data-count="expired">1<`, `data-count="critical">1<`, `data-count="warning">1<`, `data-count="ok">2<`} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s", want)
		}
	}
	if !strings.Contains(get(t, NewMux(st, &fakeRulesStore{}), "/"), `data-theme="auto"`) {
		t.Fatal("default theme must be auto")
	}
}

func TestMux_List_SortedByExpiry(t *testing.T) {
	now := time.Now()
	st := &fakeStore{current: []store.StoredRecord{
		rec("zero", "certificate", time.Time{}, nil),
		rec("late", "certificate", now.Add(90*24*time.Hour), nil),
		rec("soon", "certificate", now.Add(24*time.Hour), nil),
		rec("info", "access_key", now.Add(-30*24*time.Hour), map[string]string{"alerts": "off"}),
	}}
	body := get(t, NewMux(st, &fakeRulesStore{}), "/")
	// Informational keys never alert, so they follow everything that can.
	s, l, i, z := strings.Index(body, `data-name="soon"`), strings.Index(body, `data-name="late"`), strings.Index(body, `data-name="info"`), strings.Index(body, `data-name="zero"`)
	if s < 0 || l < 0 || i < 0 || z < 0 || !(s < l && l < i && i < z) {
		t.Fatalf("order soon=%d late=%d info=%d zero=%d", s, l, i, z)
	}
}

func TestMux_List_RowForm(t *testing.T) {
	st := &fakeStore{current: []store.StoredRecord{rec(`a&"<b`, "certificate", time.Now().Add(24*time.Hour), nil)}}
	body := get(t, NewMux(st, &fakeRulesStore{found: true, rule: rules.Rule{Muted: true, Owner: "ana"}}, Options{}), "/")
	for _, want := range []string{`name="source" value="src"`, `name="kind" value="certificate"`, `name="name" value="a&amp;&#34;&lt;b"`, `name="owner" value="ana"`} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s", want)
		}
	}
	if !regexp.MustCompile(`name="muted"[^>]*checked`).MatchString(body) {
		t.Error("muted not checked")
	}
	if strings.Contains(body, `a&"<b`) {
		t.Error("unescaped name")
	}
}

func TestTemplates_NoInlineScriptOrStyle(t *testing.T) {
	st := &fakeStore{current: []store.StoredRecord{rec("a", "certificate", time.Now(), nil)}, history: []store.StoredRecord{rec("a", "certificate", time.Now(), nil)}}
	mux := NewMux(st, &fakeRulesStore{})
	for _, p := range []string{"/", "/history?source=src&name=a&kind=certificate"} {
		checkNoInline(t, p, get(t, mux, p))
	}
	w := httptest.NewRecorder()
	renderLogin(w, "bad", nil, "auto")
	checkNoInline(t, "login", w.Body.String())
}

func checkNoInline(t *testing.T, page, body string) {
	t.Helper()
	if strings.Contains(body, "<style") || strings.Contains(body, " style=") {
		t.Errorf("%s: inline style or script", page)
	}
	for _, s := range regexp.MustCompile(`<script[^>]*>`).FindAllString(body, -1) {
		if !strings.Contains(s, "src=") {
			t.Errorf("%s: inline script %s", page, s)
		}
	}
	if !strings.Contains(body, `href="/static/app.css?v=`) {
		t.Errorf("%s: stylesheet missing", page)
	}
}

func get(t *testing.T, h http.Handler, path string) string {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("%s: %d", path, w.Code)
	}
	return w.Body.String()
}

func TestStaticHandler(t *testing.T) {
	h := StaticHandler()
	for path, want := range map[string]int{"/static/app.css": 200, "/static/app.js": 200, "/static/x": 404, "/static/../templates/list.html": 404, "/static/": 404} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != want {
			t.Errorf("%s: got %d want %d", path, w.Code, want)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/static/app.css", nil))
	if !strings.HasPrefix(w.Header().Get("Content-Type"), "text/css") {
		t.Error("css content type")
	}
}
