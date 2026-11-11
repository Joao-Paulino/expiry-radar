# Alert deduplication and health alerts (M1, issues #2 and #3)

Date: 2026-11-11 · Status: approved in conversation · Parent: [design spec](2026-11-10-expiry-radar-design.md) §6

## Behaviour

**Deduplication (#2).** The collector stores, per alert key, the last severity sent and when (`alert_state`, survives restarts). Each alert cycle:
- new non-OK state or a change of severity → send;
- back to OK after a non-OK state → send one "resolved" message, forget the state;
- same non-OK state → send again only after the reminder interval: `reminder_critical_hours` (default 24), `reminder_warning_hours` (default 0 = never);
- muted record → send nothing and forget the state, so unmuting a still-failing record alerts again.

**Health alerts (#3).** Health is stored per agent and checker (`agent_checker_health`): last seen, last success, consecutive failures, last error.
- checker failed: critical when consecutive failures ≥ `checker_fail_threshold` (default 3);
- agent silent: critical when an agent has not reported for more than `agent_stale_hours` (default 3);
- both follow the deduplication rules above; the dashboard shows an "Agents" section.

Alert keys: `expiry|<source>|<name>|<kind>`, `checker|<agent>|<checker>`, `agent|<agent>`.
Notifications carry a type (`expiry`, `checker_failed`, `agent_silent`) and a `resolved` flag; Slack/Teams/email text and the webhook JSON include both.

## Plan (TDD, one commit per step)

1. `store`: `agent_checker_health` table; `RecordCheckerHealth` keyed by (agent, checker), counts consecutive failures, success resets; `CheckerHealth` returns `LastSeenAt`, `ConsecutiveFailures`. Tests: per-agent isolation, counter, reset.
2. `alert.StateStore.Decide(ctx, key, severity, now) (send, resolved bool, err)` and `Clear(ctx, key)` over `alert_state`. Tests: first non-OK sends; same state silent; change sends; OK after non-OK sends resolved once; reminders at 24 h for critical, never for warning by default; survives a new StateStore on the same DB.
3. `alert.Engine.Evaluate` also emits checker-failed and agent-silent notifications (`FailThreshold`, `StaleAfter`). Tests: threshold boundary, stale boundary, recovery returns OK.
4. Notifiers: type- and resolved-aware text and webhook fields. Tests per type.
5. Server: config fields with defaults, alert loop uses `Decide`/`Clear`, dashboard "Agents" table, README. Tests: config defaults/JSON, loop sends once then stays quiet (fake notifier), dashboard lists agents.

Local verification: `GOPROXY=direct GOSUMDB=off go test ./...`; CI is authoritative.
