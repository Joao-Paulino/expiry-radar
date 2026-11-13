# Dashboard UI redesign

Date: 2026-11-13 · Status: approved in conversation (approach A + layout sketch)

## Why
The dashboard is unstyled HTML: a nine-column table with raw timestamps, a mute/owner form where source, name and kind are typed by hand, and no way to see at a glance what expires soon. The owner called it "horrível" and asked for a dark or light theme chosen at start-up.

## Goals
- Modern look with **dark and light themes**: collector config `"theme": "auto" | "dark" | "light"` (default `auto` = follow the OS); a ☀/☾ toggle in the header overrides it per browser (localStorage).
- **Summary cards** at the top: Expired, ≤ critical days, ≤ warning days, OK (same thresholds as alerts: `alert.Evaluate`). Clicking one filters the table.
- **Table**: state badge with relative days ("3 d", "expired 2 d ago"), exact date on hover, search box and filters (kind, source, state), sortable columns; default order by expiry, soonest first.
- **Mute / owner per row**: a ⋯ disclosure in the row with the form prefilled (hidden source/name/kind). The manual form stays, collapsed, for items not reported yet.
- **Agents and checkers** in their own section with OK / failing badges and the last error visible.
- Login and history pages share the style.

## Non-goals / anti-goals
- No CSS/JS framework, no CDN, no npm toolchain (air-gapped installs; release gate unchanged).
- Must work without JavaScript (all rows shown, server-sorted; filters/sort/theme toggle are enhancements).
- No inline scripts or styles: CSP tightened to `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`.

## Approaches
- **A (chosen):** own CSS + small vanilla JS embedded in the binary (`go:embed`), served at `/static/` without auth (login page needs it).
- B: vendored Pico.css: faster but another dependency to track, generic look.
- C: React SPA: toolchain and attack surface out of proportion.

## Decided
- Config `theme` validated (`""`/`auto`/`dark`/`light`); rendered as `<html data-theme>`; JS applies a stored override before paint.
- Severity computed server-side: `expired` (past), `critical`, `warning`, `ok`, `info` (informational cloud keys).
- `dashboard.NewMux(st, rs, opts ...Options)` and `LoginHandlers(..., opts ...Options)` with `Options{Theme}`; existing callers keep working.

## Builder's calls
Colours, spacing, typography (system font stack), English table labels with the existing bilingual buttons.
