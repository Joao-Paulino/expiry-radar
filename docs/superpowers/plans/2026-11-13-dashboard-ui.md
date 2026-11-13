# Dashboard UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Styled, themeable (dark/light/auto) dashboard with summary cards, filterable table, per-row mute/owner and agent health.
**Architecture:** Server-rendered `html/template` pages; one embedded CSS and one JS file served at `/static/` outside auth; view models computed in Go.
**Tech Stack:** Go stdlib, `embed`, vanilla JS/CSS.
**Spec:** docs/superpowers/specs/2026-11-13-dashboard-ui-design.md

## Global Constraints
- No new Go module dependencies, no CDN, no inline `<script>`/`<style>`/`style=` attributes.
- CSP exactly: `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`.
- Pages fully usable without JS.

## Review Focus
- Record with zero `ExpiresAt` → severity `unknown`, text "—", sorts last (no panic, no "expired 739000 d").
- Names/sources with `&`, quotes, `<` → escaped in links, data attributes and prefilled forms (html/template contexts).
- Unknown `theme` value in config → `Validate` error, collector refuses to start.
- `/static/` path traversal (`/static/../templates/list.html`) → 404, only `app.css`/`app.js` served.
- Empty inventory → cards show 0 and an empty-state row, no JS errors.

---

### Task 1: View model + severity
**Files:** Modify `internal/collector/dashboard/handlers.go`; Create `internal/collector/dashboard/view.go`; Test `handlers_test.go`.
**Produces:** `type Options struct{ Theme string }`; `NewMux(st store.Store, rs rules.Store, opts ...Options) *http.ServeMux`; `recordView` gains `Severity string` (`expired|critical|warning|ok|info|unknown`), `Days int`, `Relative string`, `ExpiresDate string` (2006-01-02), `ExpiresFull string` (RFC3339 UTC); `listView` gains `Theme string`, `Summary struct{Expired, Critical, Warning, OK int}`, `Kinds, Sources []string` (sorted, unique).
- [ ] Tests: `TestSeverity` table (−2d→expired "expired 2 d ago"; 3d→critical "3 d"; 20d→warning; 90d→ok; informational key 3d→info; zero time→unknown "—"); `TestMux_List_SummaryAndTheme` (body contains `data-theme="dark"` with `Options{Theme:"dark"}`, `data-theme="auto"` by default, and summary counts); `TestMux_List_SortedByExpiry` (unknown last).
- [ ] Run `go test ./internal/collector/dashboard/` → FAIL; implement `severityOf(r store.StoredRecord, now time.Time) (sev string, days int, rel string)` using `alert.Evaluate(r, now, alert.DefaultThresholds())`; sort views by ExpiresAt with zero last; → PASS; commit.

### Task 2: Static assets, CSP, config theme
**Files:** Create `internal/collector/dashboard/static/app.css`, `static/app.js`, `dashboard/static.go`; Modify `internal/collector/server/server.go`, `login.go`.
**Produces:** `dashboard.StaticHandler() http.Handler` serving only `app.css`/`app.js` with `Cache-Control: public, max-age=3600`; `Config.Theme string \`json:"theme"\`` validated; `LoginHandlers(..., opts ...Options)`.
- [ ] Tests: `TestStaticHandler` (200 + `text/css` for `/static/app.css`, 404 for `/static/x` and `/static/../templates/list.html`); server test that `/static/app.css` is reachable without auth and every response has the CSP above; `TestConfig_Validate_Theme` (`"blue"` errors; `""`,`auto`,`dark`,`light` ok).
- [ ] FAIL → implement (register `GET /static/` before the session middleware; pass `Options{Theme: cfg.Theme}`) → PASS; commit.

### Task 3: Templates, CSS, JS
**Files:** Rewrite `templates/list.html`, `history.html`, `login.html`; add `templates/layout` partial (`{{define "head"}}`); fill `app.css`, `app.js`.
- [ ] Test: `TestMux_List_RowForm` (row form contains hidden `source`,`name`,`kind` with the record's values, `muted` checked when rule muted, owner prefilled; a name `a&"<b` appears escaped); `TestTemplates_NoInlineScriptOrStyle` (rendered list/login/history contain no `<style`, no `style=`, no `<script>` without `src`).
- [ ] CSS: CSS variables for both themes (`[data-theme=dark]`, `[data-theme=light]`, `auto` via `prefers-color-scheme`), cards, badges per severity, responsive table, `<details>` menus.
- [ ] JS: theme toggle (localStorage `er-theme`, wrapped in try/catch), card click filter, search/kind/source/state filters via `data-*` on rows, header click sort, relative dates already server-side.
- [ ] PASS; manual check with Playwright screenshots (dark + light); commit.

### Task 4: README + final review
- [ ] README: `theme` config key, screenshot mention; full `go test ./...`; independent review of the branch; PR.
