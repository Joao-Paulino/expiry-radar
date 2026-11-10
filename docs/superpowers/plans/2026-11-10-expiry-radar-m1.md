# Expiry Radar — M1 (TLS checker + core platform) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a working Expiry Radar v1.0: an Agent and a Collector, connected over authenticated HTTPS, that track TLS certificate expiry end to end — collection, storage, alerting (Slack/Teams/webhook/email), a dashboard with history and mute/assign-owner rules, and JSON/CSV export — with the extension points later milestones (Vault, Azure, AWS, GCP, VMware) will plug into without any redesign.

**Architecture:** Two Go binaries (`cmd/agent`, `cmd/collector`) sharing a `checker` package that defines the `Checker` interface and the wire format (`Batch`/`Result`/`ExpiryRecord`). The Agent runs Checkers on a schedule and pushes batches to the Collector; the Collector stores everything in SQLite, evaluates alert rules, and serves a dashboard. No component ever handles a secret value — only metadata and expiry dates.

**Tech Stack:** Go (standard library `net/http`, `html/template`, `database/sql`), `mattn/go-sqlite3` (or `modernc.org/sqlite` for a CGO-free build, preferred so the binaries stay dependency-free — use `modernc.org/sqlite`), standard library `crypto/tls` for the TLS checker and for all HTTP transport.

**Spec:** `docs/superpowers/specs/2026-11-10-expiry-radar-design.md`

## Global Constraints

- Agent and Collector are single, dependency-free Go binaries (no CGO — use `modernc.org/sqlite`, not `mattn/go-sqlite3`).
- No component ever logs, transmits, or stores the actual secret/private-key/credential value — only metadata and the expiry date (spec §3, §7).
- All Agent↔Collector traffic is HTTPS (spec §7). For M1, the Collector terminates TLS directly (self-signed or provided cert via config); a reverse proxy is out of scope.
- Every credential the system uses is read-only and scoped to the minimum needed (spec §7) — no M1 Checker needs a credential beyond what `crypto/tls.Dial` needs, so this constraint is enforced starting with Vault/cloud checkers in later milestones, not M1 code.
- All log lines, including error and debug logs, must pass through the sanitizer before being written (spec §7).
- The Agent is cross-compiled and tested on Windows, RedHat, Debian, Arch, and generic Linux (spec §3, §4).
- Collector storage is SQLite by default (spec §3).
- Default alert thresholds: warning at 30 days remaining, critical at 7 days remaining, overridable per `Kind` via Collector config (spec §4, §7 example values).
- A failing Checker never blocks the others; its failure is itself an alertable condition (spec §6).
- A source that stops reporting beyond its expected interval raises its own "lost visibility" alert (spec §6).
- If the Agent cannot reach the Collector, it queues results locally and retries with backoff rather than dropping them (spec §6).

## Review Focus

- An already-expired certificate (not just one approaching expiry) — the TLS checker must still return a record with a past `ExpiresAt` rather than treating it as a connection error (owned by Task 3).
- A queued batch that is retried and lands at the Collector *after* a newer batch for the same `(source, name, kind)` — `ListCurrent` must reflect the latest `checked_at`, not the latest row id (owned by Task 5).
- A muted rule on a record that is currently critical — the alert engine must still suppress the notification while the dashboard still shows the record (as muted), not hide it (owned by Task 12, using Task 6's rules store).
- One notifier (e.g. the webhook) being unreachable must not stop the other configured notifiers (e.g. Slack, email) from being attempted for the same alert (owned by Tasks 13 and 14).
- An ingest request with a valid token but a malformed JSON body, versus one with no token at all, must be rejected as 400 and 401 respectively, and neither the token nor the raw body may ever reach an unsanitized log line (owned by Task 8, using Tasks 2 and 7).

---

## File Structure

```
go.mod
cmd/
  agent/main.go
  collector/main.go
internal/
  checker/
    checker.go
    checker_test.go
  checker/tls/
    tls.go
    tls_test.go
  logging/
    sanitize.go
    sanitize_test.go
  auth/
    token.go
    token_test.go
  agent/
    push.go
    push_test.go
    queue.go
    queue_test.go
    runner.go
    runner_test.go
  collector/
    db/
      db.go
      db_test.go
    store/
      store.go
      store_test.go
    rules/
      rules.go
      rules_test.go
    ingest/
      ingest.go
      ingest_test.go
    alert/
      engine.go
      engine_test.go
      notifiers/
        notifier.go
        webhook.go
        slack.go
        teams.go
        email.go
        notifiers_test.go
        email_test.go
    export/
      export.go
      export_test.go
    dashboard/
      handlers.go
      handlers_test.go
      templates/
        list.html
        history.html
scripts/
  build-agent.sh
```

---

### Task 1: Core checker types and wire format

**Files:**
- Create: `internal/checker/checker.go`
- Test: `internal/checker/checker_test.go`

**Interfaces:**
- Produces: `checker.ExpiryRecord{Source, Name, Kind string; ExpiresAt time.Time; Metadata map[string]string}`, `checker.Checker` interface (`Name() string`, `Kind() string`, `Check(ctx context.Context) ([]ExpiryRecord, error)`), `checker.Result{CheckerName, ErrMsg string; Records []ExpiryRecord}`, `checker.Batch{AgentID string; Results []Result}`, `(ExpiryRecord) Validate() error`. Every later task imports these from `internal/checker`.

- [ ] **Step 1: Write the failing test for `ExpiryRecord.Validate()`**

```go
func TestExpiryRecord_Validate(t *testing.T) {
    valid := ExpiryRecord{Source: "host:443", Name: "example.com", Kind: "certificate", ExpiresAt: time.Now().Add(24 * time.Hour)}
    if err := valid.Validate(); err != nil {
        t.Fatalf("expected valid record to pass, got %v", err)
    }
    missingSource := valid
    missingSource.Source = ""
    if err := missingSource.Validate(); err == nil {
        t.Fatal("expected error for missing Source")
    }
    zeroExpiry := valid
    zeroExpiry.ExpiresAt = time.Time{}
    if err := zeroExpiry.Validate(); err == nil {
        t.Fatal("expected error for zero ExpiresAt")
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/checker/... -run TestExpiryRecord_Validate -v`
Expected: FAIL (`ExpiryRecord` undefined)

- [ ] **Step 3: Implement the types and `Validate()` in `internal/checker/checker.go`**

`Validate()` returns an error if `Source`, `Name`, or `Kind` is empty, or `ExpiresAt` is the zero time. `Checker`, `Result`, and `Batch` carry only the field types listed in Produces above, with JSON tags `source`, `name`, `kind`, `expires_at`, `metadata`, `checker_name`, `err_msg`, `records`, `agent_id`, `results` (all `omitempty` except the required identity fields).

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/checker/... -run TestExpiryRecord_Validate -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/checker/checker.go internal/checker/checker_test.go go.mod go.sum
git commit -m "feat(checker): add core ExpiryRecord/Checker/Batch types"
```

---

### Task 2: Log sanitization

**Files:**
- Create: `internal/logging/sanitize.go`
- Test: `internal/logging/sanitize_test.go`

**Interfaces:**
- Produces: `logging.Sanitize(s string) string`. Every package that writes a log line containing user- or external-supplied data calls this first (Tasks 8, 9, 11, 13, 14, 16, 17, 18).

- [ ] **Step 1: Write the failing tests**

```go
func TestSanitize_KeyValuePairs(t *testing.T) {
    in := `connecting with password=supersecret123 and token: abc.def.ghi`
    out := Sanitize(in)
    if strings.Contains(out, "supersecret123") || strings.Contains(out, "abc.def.ghi") {
        t.Fatalf("secret leaked in output: %q", out)
    }
    if !strings.Contains(out, "[REDACTED]") {
        t.Fatalf("expected redaction marker, got %q", out)
    }
}

func TestSanitize_PEMBlock(t *testing.T) {
    in := "cert:\n-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG\n-----END CERTIFICATE-----\ndone"
    out := Sanitize(in)
    if strings.Contains(out, "MIIBIjANBgkqhkiG") {
        t.Fatalf("PEM body leaked: %q", out)
    }
    if !strings.Contains(out, "[REDACTED-PEM]") {
        t.Fatalf("expected PEM redaction marker, got %q", out)
    }
}

func TestSanitize_NoSecrets(t *testing.T) {
    in := "checker tls-checker completed in 120ms"
    if out := Sanitize(in); out != in {
        t.Fatalf("expected unchanged string, got %q", out)
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/logging/... -v`
Expected: FAIL (`Sanitize` undefined)

- [ ] **Step 3: Implement `Sanitize(s string) string` in `internal/logging/sanitize.go`**

Two passes, in this order:
1. Replace every PEM block with `[REDACTED-PEM]` using the regex `` `(?s)-----BEGIN [^-]+-----.*?-----END [^-]+-----` `` (the `(?s)` flag lets `.` match newlines).
2. Replace the value half of any `key=value` or `key: value` pair whose key case-insensitively matches `password|secret|token|apikey|api_key|access_key|private_key` with `[REDACTED]`, using the regex `` `(?i)(password|secret|token|apikey|api_key|access_key|private_key)\s*[:=]\s*\S+` `` and replacing each match with `$1=[REDACTED]`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/logging/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/logging/
git commit -m "feat(logging): add secret-redacting log sanitizer"
```

---

### Task 3: TLS checker

**Files:**
- Create: `internal/checker/tls/tls.go`
- Test: `internal/checker/tls/tls_test.go`

**Interfaces:**
- Consumes: `checker.ExpiryRecord`, `checker.Checker` (Task 1).
- Produces: `tls.Target{Host string; Port int; StartTLS string}`, `tls.New(targets []Target) *Checker`, `(*Checker) Name() string`, `(*Checker) Kind() string` (returns `"certificate"`), `(*Checker) Check(ctx context.Context) ([]checker.ExpiryRecord, error)`. Consumed by Task 11 (Agent runner wiring) and Task 18 (cmd/agent).

- [ ] **Step 1: Write the failing tests**

```go
func TestChecker_Check_ReturnsCertExpiry(t *testing.T) {
    srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
    defer srv.Close()
    host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
    port, _ := strconv.Atoi(portStr)

    c := New([]Target{{Host: host, Port: port}})
    // The checker must accept the test server's self-signed cert for this
    // test; inject srv.Client().Transport's TLS config (InsecureSkipVerify)
    // via a Checker field/option added in Step 3.
    records, err := c.Check(context.Background())
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if len(records) != 1 {
        t.Fatalf("expected 1 record, got %d", len(records))
    }
    want := srv.Certificate().NotAfter
    if !records[0].ExpiresAt.Equal(want) {
        t.Fatalf("ExpiresAt = %v, want %v", records[0].ExpiresAt, want)
    }
    if records[0].Kind != "certificate" {
        t.Fatalf("Kind = %q, want %q", records[0].Kind, "certificate")
    }
}

func TestChecker_Check_PartialFailureKeepsOtherResults(t *testing.T) {
    srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
    defer srv.Close()
    host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
    port, _ := strconv.Atoi(portStr)

    c := New([]Target{
        {Host: host, Port: port},
        {Host: "127.0.0.1", Port: 1}, // nothing listening: unreachable
    })
    records, err := c.Check(context.Background())
    if err == nil {
        t.Fatal("expected a non-nil error for the unreachable target")
    }
    if len(records) != 1 {
        t.Fatalf("expected 1 record from the reachable target, got %d", len(records))
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/checker/tls/... -v`
Expected: FAIL (`New`/`Target`/`Checker` undefined)

- [ ] **Step 3: Implement `tls.Target`, `tls.New`, and `(*Checker).Check` in `internal/checker/tls/tls.go`**

- Add an exported field or functional option so tests can set `tls.Config.InsecureSkipVerify` on the dialer (e.g. a `Checker.TLSConfig *tls.Config` field defaulting to nil, meaning "use default verification"); production code (Task 18) never sets it.
- For each `Target`: if `StartTLS == ""`, dial with `tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", host:port, cfg)`. If `StartTLS == "smtp"`, dial plain TCP, perform the SMTP `STARTTLS` handshake (reuse the approach from `check-cert-renewal.sh`'s `openssl s_client -starttls smtp`, implemented with `net/smtp` or a raw STARTTLS command exchange), then wrap the connection with `tls.Client`.
- Read `conn.ConnectionState().PeerCertificates[0]` for the leaf certificate; build `checker.ExpiryRecord{Source: "host:port", Name: cert.Subject.CommonName, Kind: "certificate", ExpiresAt: cert.NotAfter, Metadata: {"issuer": cert.Issuer.CommonName, "serial": cert.SerialNumber.String()}}`.
- Collect per-target errors with `errors.Join`; return all successfully-collected records alongside the joined error (never both nil and empty when at least one target failed).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/checker/tls/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/checker/tls/
git commit -m "feat(checker/tls): add generic TLS certificate expiry checker"
```

---

### Task 4: Collector database bootstrap

**Files:**
- Create: `internal/collector/db/db.go`
- Test: `internal/collector/db/db_test.go`

**Interfaces:**
- Produces: `db.Open(path string) (*sql.DB, error)` — opens (creating if absent) a `modernc.org/sqlite` database at `path` and runs all `CREATE TABLE IF NOT EXISTS` migrations below. Consumed by Tasks 5, 6, 17.

- [ ] **Step 1: Write the failing test**

```go
func TestOpen_CreatesSchema(t *testing.T) {
    dir := t.TempDir()
    database, err := Open(filepath.Join(dir, "test.db"))
    if err != nil {
        t.Fatalf("Open failed: %v", err)
    }
    defer database.Close()

    for _, table := range []string{"expiry_records", "checker_health", "rules"} {
        var name string
        err := database.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&name)
        if err != nil {
            t.Fatalf("table %q not created: %v", table, err)
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/collector/db/... -v`
Expected: FAIL (`Open` undefined)

- [ ] **Step 3: Implement `Open` in `internal/collector/db/db.go`**

```sql
CREATE TABLE IF NOT EXISTS expiry_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    metadata_json TEXT NOT NULL,
    reported_by TEXT NOT NULL,
    checked_at DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_expiry_records_key ON expiry_records(source, name, kind);

CREATE TABLE IF NOT EXISTS checker_health (
    checker_name TEXT PRIMARY KEY,
    last_success_at DATETIME,
    last_error TEXT NOT NULL DEFAULT '',
    reported_by TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS rules (
    source TEXT NOT NULL,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    muted BOOLEAN NOT NULL DEFAULT 0,
    owner TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (source, name, kind)
);
```

Open with `sql.Open("sqlite", path)` (the `modernc.org/sqlite` driver registers itself under the name `"sqlite"`), then `Exec` the three statements above in order.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/collector/db/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/collector/db/ go.mod go.sum
git commit -m "feat(collector/db): add SQLite schema bootstrap"
```

---

### Task 5: Records store

**Files:**
- Create: `internal/collector/store/store.go`
- Test: `internal/collector/store/store_test.go`

**Interfaces:**
- Consumes: `db.Open` (Task 4), `checker.ExpiryRecord` (Task 1).
- Produces: `store.Store` interface (`SaveRecords(ctx, agentID string, records []checker.ExpiryRecord) error`; `RecordCheckerHealth(ctx, checkerName, reportedBy string, checkErr error) error`; `ListCurrent(ctx) ([]StoredRecord, error)`; `History(ctx, source, name, kind string) ([]StoredRecord, error)`; `CheckerHealth(ctx) ([]CheckerHealth, error)`), `store.StoredRecord{checker.ExpiryRecord; ReportedBy string; CheckedAt time.Time}`, `store.CheckerHealth{CheckerName string; LastSuccessAt time.Time; LastError, ReportedBy string}`, `store.NewSQLite(database *sql.DB) *SQLite`. Consumed by Tasks 8, 12, 15, 16, 17.

- [ ] **Step 1: Write the failing tests**

```go
func TestSQLite_ListCurrent_ReturnsLatestPerKey(t *testing.T) {
    s := newTestStore(t)
    ctx := context.Background()
    old := checker.ExpiryRecord{Source: "a", Name: "b", Kind: "certificate", ExpiresAt: time.Now().Add(72 * time.Hour)}
    if err := s.SaveRecords(ctx, "agent-1", []checker.ExpiryRecord{old}); err != nil {
        t.Fatal(err)
    }
    time.Sleep(10 * time.Millisecond) // ensure a distinct checked_at
    newer := old
    newer.ExpiresAt = time.Now().Add(48 * time.Hour)
    if err := s.SaveRecords(ctx, "agent-1", []checker.ExpiryRecord{newer}); err != nil {
        t.Fatal(err)
    }

    current, err := s.ListCurrent(ctx)
    if err != nil {
        t.Fatal(err)
    }
    if len(current) != 1 {
        t.Fatalf("expected 1 current record, got %d", len(current))
    }
    if !current[0].ExpiresAt.Equal(newer.ExpiresAt) {
        t.Fatalf("ListCurrent returned stale ExpiresAt %v, want %v", current[0].ExpiresAt, newer.ExpiresAt)
    }
}

func TestSQLite_History_ReturnsAllSnapshotsOrdered(t *testing.T) {
    s := newTestStore(t)
    ctx := context.Background()
    rec := checker.ExpiryRecord{Source: "a", Name: "b", Kind: "certificate", ExpiresAt: time.Now().Add(72 * time.Hour)}
    s.SaveRecords(ctx, "agent-1", []checker.ExpiryRecord{rec})
    time.Sleep(10 * time.Millisecond)
    rec.ExpiresAt = time.Now().Add(48 * time.Hour)
    s.SaveRecords(ctx, "agent-1", []checker.ExpiryRecord{rec})

    hist, err := s.History(ctx, "a", "b", "certificate")
    if err != nil {
        t.Fatal(err)
    }
    if len(hist) != 2 {
        t.Fatalf("expected 2 history rows, got %d", len(hist))
    }
    if !hist[0].CheckedAt.Before(hist[1].CheckedAt) {
        t.Fatal("expected history ordered oldest first")
    }
}

func TestSQLite_RecordCheckerHealth_SuccessAndFailure(t *testing.T) {
    s := newTestStore(t)
    ctx := context.Background()
    if err := s.RecordCheckerHealth(ctx, "tls-checker", "agent-1", nil); err != nil {
        t.Fatal(err)
    }
    if err := s.RecordCheckerHealth(ctx, "tls-checker", "agent-1", errors.New("boom")); err != nil {
        t.Fatal(err)
    }
    health, err := s.CheckerHealth(ctx)
    if err != nil {
        t.Fatal(err)
    }
    if len(health) != 1 || health[0].LastError != "boom" {
        t.Fatalf("got %+v, want LastError=boom", health)
    }
    if health[0].LastSuccessAt.IsZero() {
        t.Fatal("expected LastSuccessAt to be preserved from the earlier successful call")
    }
}
```

`newTestStore(t)` is a small unexported test helper in `store_test.go` that calls `db.Open(filepath.Join(t.TempDir(), "test.db"))` and returns `NewSQLite(database)`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/collector/store/... -v`
Expected: FAIL (`NewSQLite` undefined)

- [ ] **Step 3: Implement `NewSQLite` and the `Store` methods in `internal/collector/store/store.go`**

- `SaveRecords`: for each record, `INSERT INTO expiry_records (source, name, kind, expires_at, metadata_json, reported_by, checked_at) VALUES (...)` with `metadata_json` as `json.Marshal(record.Metadata)` and `checked_at = time.Now().UTC()`.
- `ListCurrent`: `SELECT ... FROM expiry_records e WHERE checked_at = (SELECT MAX(checked_at) FROM expiry_records WHERE source=e.source AND name=e.name AND kind=e.kind)`.
- `History`: `SELECT ... FROM expiry_records WHERE source=? AND name=? AND kind=? ORDER BY checked_at ASC`.
- `RecordCheckerHealth`: upsert via `INSERT INTO checker_health (...) VALUES (...) ON CONFLICT(checker_name) DO UPDATE SET ...`; on success (`checkErr == nil`) set `last_success_at = now` and leave `last_error` untouched only if there is no new error to set — i.e. a successful call does not need to touch `last_error` at all; on failure set `last_error` to `checkErr.Error()` and leave `last_success_at` untouched.
- `CheckerHealth`: `SELECT checker_name, last_success_at, last_error, reported_by FROM checker_health`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/collector/store/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/collector/store/
git commit -m "feat(collector/store): add SQLite-backed expiry record store"
```

---

### Task 6: Rules store

**Files:**
- Create: `internal/collector/rules/rules.go`
- Test: `internal/collector/rules/rules_test.go`

**Interfaces:**
- Consumes: `db.Open` (Task 4).
- Produces: `rules.Rule{Source, Name, Kind string; Muted bool; Owner string}`, `rules.Store` interface (`Get(ctx, source, name, kind string) (Rule, bool, error)`; `Upsert(ctx, r Rule) error`; `List(ctx) ([]Rule, error)`), `rules.NewSQLite(database *sql.DB) *SQLite`. Consumed by Tasks 12, 16.

- [ ] **Step 1: Write the failing tests**

```go
func TestSQLite_Upsert_ThenGet(t *testing.T) {
    s := newTestRulesStore(t)
    ctx := context.Background()
    r := Rule{Source: "a", Name: "b", Kind: "certificate", Muted: true, Owner: "joao"}
    if err := s.Upsert(ctx, r); err != nil {
        t.Fatal(err)
    }
    got, found, err := s.Get(ctx, "a", "b", "certificate")
    if err != nil || !found {
        t.Fatalf("Get failed: found=%v err=%v", found, err)
    }
    if got != r {
        t.Fatalf("Get = %+v, want %+v", got, r)
    }
}

func TestSQLite_Get_NotFound(t *testing.T) {
    s := newTestRulesStore(t)
    _, found, err := s.Get(context.Background(), "missing", "missing", "certificate")
    if err != nil {
        t.Fatal(err)
    }
    if found {
        t.Fatal("expected found=false for a rule that was never set")
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/collector/rules/... -v`
Expected: FAIL (`NewSQLite` undefined)

- [ ] **Step 3: Implement `NewSQLite` and the `Store` methods in `internal/collector/rules/rules.go`**

`Upsert`: `INSERT INTO rules (...) VALUES (...) ON CONFLICT(source, name, kind) DO UPDATE SET muted=excluded.muted, owner=excluded.owner`. `Get`: `SELECT muted, owner FROM rules WHERE source=? AND name=? AND kind=?`, returning `found=false` on `sql.ErrNoRows`. `List`: `SELECT source, name, kind, muted, owner FROM rules`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/collector/rules/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/collector/rules/
git commit -m "feat(collector/rules): add mute/assign-owner rules store"
```

---

### Task 7: Auth middleware

**Files:**
- Create: `internal/auth/token.go`
- Test: `internal/auth/token_test.go`

**Interfaces:**
- Produces: `auth.Middleware(validTokens []string, next http.Handler) http.Handler`, `auth.AttachToken(req *http.Request, token string)`. Consumed by Tasks 8 (Collector) and 9 (Agent).

- [ ] **Step 1: Write the failing tests**

```go
func TestMiddleware_RejectsMissingAndWrongToken(t *testing.T) {
    inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
    h := Middleware([]string{"good-token"}, inner)

    req := httptest.NewRequest("GET", "/", nil)
    rec := httptest.NewRecorder()
    h.ServeHTTP(rec, req)
    if rec.Code != http.StatusUnauthorized {
        t.Fatalf("missing token: got %d, want 401", rec.Code)
    }

    req2 := httptest.NewRequest("GET", "/", nil)
    AttachToken(req2, "wrong-token")
    rec2 := httptest.NewRecorder()
    h.ServeHTTP(rec2, req2)
    if rec2.Code != http.StatusUnauthorized {
        t.Fatalf("wrong token: got %d, want 401", rec2.Code)
    }
}

func TestMiddleware_AcceptsValidToken(t *testing.T) {
    inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
    h := Middleware([]string{"good-token"}, inner)
    req := httptest.NewRequest("GET", "/", nil)
    AttachToken(req, "good-token")
    rec := httptest.NewRecorder()
    h.ServeHTTP(rec, req)
    if rec.Code != http.StatusOK {
        t.Fatalf("got %d, want 200", rec.Code)
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/auth/... -v`
Expected: FAIL (`Middleware`/`AttachToken` undefined)

- [ ] **Step 3: Implement `Middleware` and `AttachToken` in `internal/auth/token.go`**

`AttachToken` sets `req.Header.Set("Authorization", "Bearer "+token)`. `Middleware` reads the `Authorization` header, strips a `"Bearer "` prefix, and compares it against `validTokens` using `crypto/subtle.ConstantTimeCompare` for each candidate (to avoid a timing side-channel); on no match, respond `401` and return without calling `next`; the raw header value is never passed to a logger.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/auth/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/auth/
git commit -m "feat(auth): add bearer-token middleware for agent-collector auth"
```

---

### Task 8: Collector ingest endpoint

**Files:**
- Create: `internal/collector/ingest/ingest.go`
- Test: `internal/collector/ingest/ingest_test.go`

**Interfaces:**
- Consumes: `checker.Batch` (Task 1), `store.Store` (Task 5), `logging.Sanitize` (Task 2).
- Produces: `ingest.Handler(st store.Store) http.HandlerFunc`. Consumed by Task 17 (wrapped with `auth.Middleware` from Task 7).

- [ ] **Step 1: Write the failing tests**

```go
type fakeStore struct {
    saved  []checker.ExpiryRecord
    health []struct{ name, reportedBy string; err error }
}
func (f *fakeStore) SaveRecords(ctx context.Context, agentID string, records []checker.ExpiryRecord) error {
    f.saved = append(f.saved, records...)
    return nil
}
func (f *fakeStore) RecordCheckerHealth(ctx context.Context, name, reportedBy string, err error) error {
    f.health = append(f.health, struct{ name, reportedBy string; err error }{name, reportedBy, err})
    return nil
}
func (f *fakeStore) ListCurrent(ctx context.Context) ([]store.StoredRecord, error) { return nil, nil }
func (f *fakeStore) History(ctx context.Context, source, name, kind string) ([]store.StoredRecord, error) { return nil, nil }
func (f *fakeStore) CheckerHealth(ctx context.Context) ([]store.CheckerHealth, error) { return nil, nil }

func TestHandler_ValidBatch_SavesRecordsAndHealth(t *testing.T) {
    fs := &fakeStore{}
    h := Handler(fs)
    batch := checker.Batch{AgentID: "agent-1", Results: []checker.Result{
        {CheckerName: "tls-checker", Records: []checker.ExpiryRecord{{Source: "a", Name: "b", Kind: "certificate", ExpiresAt: time.Now()}}},
        {CheckerName: "other-checker", ErrMsg: "connection refused"},
    }}
    body, _ := json.Marshal(batch)
    req := httptest.NewRequest("POST", "/ingest", bytes.NewReader(body))
    rec := httptest.NewRecorder()
    h(rec, req)
    if rec.Code != http.StatusNoContent {
        t.Fatalf("got %d, want 204", rec.Code)
    }
    if len(fs.saved) != 1 {
        t.Fatalf("expected 1 saved record, got %d", len(fs.saved))
    }
    if len(fs.health) != 2 {
        t.Fatalf("expected 2 health updates, got %d", len(fs.health))
    }
}

func TestHandler_MalformedJSON_Returns400(t *testing.T) {
    h := Handler(&fakeStore{})
    req := httptest.NewRequest("POST", "/ingest", strings.NewReader("{not json"))
    rec := httptest.NewRecorder()
    h(rec, req)
    if rec.Code != http.StatusBadRequest {
        t.Fatalf("got %d, want 400", rec.Code)
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/collector/ingest/... -v`
Expected: FAIL (`Handler` undefined)

- [ ] **Step 3: Implement `Handler` in `internal/collector/ingest/ingest.go`**

Decode the request body into a `checker.Batch`; on decode error, respond `400` and log `logging.Sanitize(err.Error())` (never the raw body). For each `Result`: if `ErrMsg == ""`, call `st.SaveRecords(ctx, batch.AgentID, result.Records)` then `st.RecordCheckerHealth(ctx, result.CheckerName, batch.AgentID, nil)`; otherwise call `st.RecordCheckerHealth(ctx, result.CheckerName, batch.AgentID, errors.New(result.ErrMsg))`. On any store error, respond `500` and log the sanitized error. On success, respond `204`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/collector/ingest/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/collector/ingest/
git commit -m "feat(collector/ingest): add batch ingestion endpoint"
```

---

### Task 9: Agent pusher

**Files:**
- Create: `internal/agent/push.go`
- Test: `internal/agent/push_test.go`

**Interfaces:**
- Consumes: `checker.Batch` (Task 1), `auth.AttachToken` (Task 7).
- Produces: `agent.NewPusher(collectorURL, token string) *Pusher`, `(*Pusher) Push(ctx context.Context, b checker.Batch) error`. Consumed by Tasks 11, 18.

- [ ] **Step 1: Write the failing tests**

```go
func TestPusher_Push_SendsAuthenticatedJSON(t *testing.T) {
    var gotAuth string
    var gotBatch checker.Batch
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        gotAuth = r.Header.Get("Authorization")
        json.NewDecoder(r.Body).Decode(&gotBatch)
        w.WriteHeader(http.StatusNoContent)
    }))
    defer srv.Close()

    p := NewPusher(srv.URL, "my-token")
    b := checker.Batch{AgentID: "agent-1", Results: []checker.Result{{CheckerName: "tls-checker"}}}
    if err := p.Push(context.Background(), b); err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if gotAuth != "Bearer my-token" {
        t.Fatalf("Authorization = %q", gotAuth)
    }
    if gotBatch.AgentID != "agent-1" {
        t.Fatalf("AgentID = %q", gotBatch.AgentID)
    }
}

func TestPusher_Push_NonSuccessStatusIsError(t *testing.T) {
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusUnauthorized)
    }))
    defer srv.Close()
    p := NewPusher(srv.URL, "bad-token")
    if err := p.Push(context.Background(), checker.Batch{}); err == nil {
        t.Fatal("expected an error for a 401 response")
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/agent/... -run TestPusher -v`
Expected: FAIL (`NewPusher` undefined)

- [ ] **Step 3: Implement `NewPusher` and `Push` in `internal/agent/push.go`**

`Push` marshals `b` to JSON, builds a `POST {collectorURL}/ingest` request, calls `auth.AttachToken(req, token)`, sends it with an `*http.Client` with a reasonable timeout (e.g. 15s), and returns an error if the status code is not `204`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/agent/... -run TestPusher -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/agent/push.go internal/agent/push_test.go
git commit -m "feat(agent): add authenticated push client"
```

---

### Task 10: Agent local retry queue

**Files:**
- Create: `internal/agent/queue.go`
- Test: `internal/agent/queue_test.go`

**Interfaces:**
- Consumes: `checker.Batch` (Task 1).
- Produces: `agent.NewQueue(path string) *Queue`, `(*Queue) Enqueue(b checker.Batch) error`, `(*Queue) Drain(ctx context.Context, send func(checker.Batch) error) error`. Consumed by Tasks 11, 18.

- [ ] **Step 1: Write the failing tests**

```go
func TestQueue_Drain_SendsInOrderAndEmpties(t *testing.T) {
    q := NewQueue(filepath.Join(t.TempDir(), "queue.jsonl"))
    b1 := checker.Batch{AgentID: "1"}
    b2 := checker.Batch{AgentID: "2"}
    q.Enqueue(b1)
    q.Enqueue(b2)

    var got []checker.Batch
    err := q.Drain(context.Background(), func(b checker.Batch) error {
        got = append(got, b)
        return nil
    })
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if len(got) != 2 || got[0].AgentID != "1" || got[1].AgentID != "2" {
        t.Fatalf("got %+v", got)
    }

    var secondDrain []checker.Batch
    q.Drain(context.Background(), func(b checker.Batch) error { secondDrain = append(secondDrain, b); return nil })
    if len(secondDrain) != 0 {
        t.Fatalf("expected queue empty after first drain, got %d items", len(secondDrain))
    }
}

func TestQueue_Drain_StopsOnFirstFailureAndKeepsBacklog(t *testing.T) {
    q := NewQueue(filepath.Join(t.TempDir(), "queue.jsonl"))
    q.Enqueue(checker.Batch{AgentID: "1"})
    q.Enqueue(checker.Batch{AgentID: "2"})

    calls := 0
    err := q.Drain(context.Background(), func(b checker.Batch) error {
        calls++
        return errors.New("still unreachable")
    })
    if err == nil {
        t.Fatal("expected Drain to return the send error")
    }
    if calls != 1 {
        t.Fatalf("expected Drain to stop after the first failure, got %d calls", calls)
    }

    var remaining []checker.Batch
    q.Drain(context.Background(), func(b checker.Batch) error { remaining = append(remaining, b); return nil })
    if len(remaining) != 2 {
        t.Fatalf("expected both batches still queued, got %d", len(remaining))
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/agent/... -run TestQueue -v`
Expected: FAIL (`NewQueue` undefined)

- [ ] **Step 3: Implement `NewQueue`, `Enqueue`, and `Drain` in `internal/agent/queue.go`**

Store the queue as one JSON object per line (JSONL) in the file at `path`, appending on `Enqueue`. `Drain` reads all lines, and for each in order calls `send`; on the first error, stop immediately, rewrite the file with only the un-sent remaining lines (including the one that just failed and everything after it), and return that error. On full success, remove the file (or truncate it).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/agent/... -run TestQueue -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/agent/queue.go internal/agent/queue_test.go
git commit -m "feat(agent): add local JSONL retry queue"
```

---

### Task 11: Agent runner

**Files:**
- Create: `internal/agent/runner.go`
- Test: `internal/agent/runner_test.go`

**Interfaces:**
- Consumes: `checker.Checker`, `checker.Batch`, `checker.Result` (Task 1), `*Pusher` (Task 9), `*Queue` (Task 10), `logging.Sanitize` (Task 2).
- Produces: `agent.NewRunner(agentID string, checkers []checker.Checker, pusher *Pusher, queue *Queue) *Runner`, `(*Runner) RunOnce(ctx context.Context) error`. Consumed by Task 18.

- [ ] **Step 1: Write the failing tests**

```go
type fakeChecker struct {
    name string
    records []checker.ExpiryRecord
    err error
}
func (f *fakeChecker) Name() string { return f.name }
func (f *fakeChecker) Kind() string { return "certificate" }
func (f *fakeChecker) Check(ctx context.Context) ([]checker.ExpiryRecord, error) { return f.records, f.err }

func TestRunner_RunOnce_IsolatesCheckerFailureAndPushesBoth(t *testing.T) {
    var gotBatch checker.Batch
    srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        json.NewDecoder(r.Body).Decode(&gotBatch)
        w.WriteHeader(http.StatusNoContent)
    }))
    defer srv.Close()

    okChecker := &fakeChecker{name: "ok-checker", records: []checker.ExpiryRecord{{Source: "a", Name: "b", Kind: "certificate", ExpiresAt: time.Now()}}}
    failChecker := &fakeChecker{name: "fail-checker", err: errors.New("unreachable")}

    r := NewRunner("agent-1", []checker.Checker{okChecker, failChecker}, NewPusher(srv.URL, "t"), NewQueue(filepath.Join(t.TempDir(), "q.jsonl")))
    if err := r.RunOnce(context.Background()); err != nil {
        t.Fatalf("RunOnce should isolate checker failures, got %v", err)
    }
    if len(gotBatch.Results) != 2 {
        t.Fatalf("expected 2 results in the pushed batch, got %d", len(gotBatch.Results))
    }
    var sawFail bool
    for _, res := range gotBatch.Results {
        if res.CheckerName == "fail-checker" {
            sawFail = true
            if res.ErrMsg != "unreachable" {
                t.Fatalf("ErrMsg = %q, want %q", res.ErrMsg, "unreachable")
            }
        }
    }
    if !sawFail {
        t.Fatal("expected fail-checker's result to be included despite its error")
    }
}

func TestRunner_RunOnce_QueuesOnPushFailure(t *testing.T) {
    unreachableURL := "http://127.0.0.1:1" // nothing listening
    qPath := filepath.Join(t.TempDir(), "q.jsonl")
    r := NewRunner("agent-1", []checker.Checker{&fakeChecker{name: "c", records: []checker.ExpiryRecord{{Source: "a", Name: "b", Kind: "certificate", ExpiresAt: time.Now()}}}}, NewPusher(unreachableURL, "t"), NewQueue(qPath))
    r.RunOnce(context.Background())

    if _, err := os.Stat(qPath); err != nil {
        t.Fatalf("expected queue file to exist after a failed push, got %v", err)
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/agent/... -run TestRunner -v`
Expected: FAIL (`NewRunner` undefined)

- [ ] **Step 3: Implement `NewRunner` and `RunOnce` in `internal/agent/runner.go`**

`RunOnce`: first call `r.Queue.Drain(ctx, r.Pusher.Push)` to flush any backlog, logging (sanitized) and continuing if it errors. Then, for each `Checker`, call `Check(ctx)`; build one `checker.Result` per checker (`ErrMsg: err.Error()` if non-nil, else `Records: records`). Assemble `checker.Batch{AgentID: r.AgentID, Results: results}` and call `r.Pusher.Push(ctx, batch)`; on error, call `r.Queue.Enqueue(batch)` instead of dropping it. Return nil unless `Enqueue` itself fails (a local disk error), in which case return that error.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/agent/... -run TestRunner -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/agent/runner.go internal/agent/runner_test.go
git commit -m "feat(agent): add runner that isolates checker failures and queues on push failure"
```

---

### Task 12: Alerting engine

**Files:**
- Create: `internal/collector/alert/engine.go`
- Test: `internal/collector/alert/engine_test.go`

**Interfaces:**
- Consumes: `store.Store` (Task 5), `rules.Store` (Task 6).
- Produces: `alert.Thresholds map[string]alert.Threshold` where `alert.Threshold{WarnDays, CritDays int}`, `alert.DefaultThresholds()` (returns every kind mapped to `{WarnDays: 30, CritDays: 7}`), `alert.Severity` (`"ok"`, `"warning"`, `"critical"`, `"unknown"`), `alert.Evaluate(record store.StoredRecord, now time.Time, thresholds Thresholds) Severity`, `alert.Engine{Store store.Store; Rules rules.Store; Thresholds Thresholds; StaleAfter time.Duration}`, `(*Engine) Evaluate(ctx context.Context, now time.Time) ([]alert.Notification, error)` where `alert.Notification{Record store.StoredRecord; Severity Severity; Muted bool}`. Consumed by Tasks 13, 14, 17.

- [ ] **Step 1: Write the failing tests**

```go
func TestEvaluate_SeverityByDaysRemaining(t *testing.T) {
    now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
    th := DefaultThresholds()
    cases := []struct{ days int; want Severity }{
        {40, "ok"}, {30, "warning"}, {10, "warning"}, {7, "critical"}, {0, "critical"}, {-5, "critical"},
    }
    for _, c := range cases {
        rec := store.StoredRecord{ExpiryRecord: checker.ExpiryRecord{Kind: "certificate", ExpiresAt: now.AddDate(0, 0, c.days)}}
        if got := Evaluate(rec, now, th); got != c.want {
            t.Errorf("days=%d: got %q, want %q", c.days, got, c.want)
        }
    }
}

func TestEngine_Evaluate_MutedRecordStillReturnedButMarkedMuted(t *testing.T) {
    st := &fakeStore{current: []store.StoredRecord{{ExpiryRecord: checker.ExpiryRecord{Source: "a", Name: "b", Kind: "certificate", ExpiresAt: time.Now().Add(1 * time.Hour)}}}}
    rs := &fakeRulesStore{rule: rules.Rule{Source: "a", Name: "b", Kind: "certificate", Muted: true}}
    e := &Engine{Store: st, Rules: rs, Thresholds: DefaultThresholds()}
    notifications, err := e.Evaluate(context.Background(), time.Now())
    if err != nil {
        t.Fatal(err)
    }
    if len(notifications) != 1 {
        t.Fatalf("expected the muted record to still appear, got %d", len(notifications))
    }
    if !notifications[0].Muted {
        t.Fatal("expected Muted=true")
    }
    if notifications[0].Severity != "critical" {
        t.Fatalf("Severity = %q, want critical", notifications[0].Severity)
    }
}
```

`fakeStore` and `fakeRulesStore` are small unexported test doubles in `engine_test.go` implementing just the methods `Evaluate` calls (`ListCurrent`/`CheckerHealth` and `Get`, respectively).

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/collector/alert/... -v`
Expected: FAIL (`Evaluate`/`Engine` undefined)

- [ ] **Step 3: Implement the types and functions in `internal/collector/alert/engine.go`**

`Evaluate(record, now, thresholds)`: compute `daysRemaining := int(record.ExpiresAt.Sub(now).Hours() / 24)`; look up `thresholds[record.Kind]` (fall back to the zero `Threshold` — treat a missing kind as `{WarnDays: 30, CritDays: 7}` via `DefaultThresholds()`'s values if the map has no entry); return `"critical"` if `daysRemaining <= CritDays`, `"warning"` if `daysRemaining <= WarnDays`, else `"ok"`. `(*Engine).Evaluate`: call `e.Store.ListCurrent(ctx)`; for each record call `e.Rules.Get(ctx, record.Source, record.Name, record.Kind)` and `Evaluate(record, now, e.Thresholds)`; build one `Notification` per record (muted ones are included with `Muted: true`, not filtered out here — filtering happens in the notifier step, Task 13).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/collector/alert/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/collector/alert/engine.go internal/collector/alert/engine_test.go
git commit -m "feat(collector/alert): add severity evaluation engine"
```

---

### Task 13: Webhook, Slack, and Teams notifiers

**Files:**
- Create: `internal/collector/alert/notifiers/notifier.go`
- Create: `internal/collector/alert/notifiers/webhook.go`
- Create: `internal/collector/alert/notifiers/slack.go`
- Create: `internal/collector/alert/notifiers/teams.go`
- Test: `internal/collector/alert/notifiers/notifiers_test.go`

**Interfaces:**
- Consumes: `alert.Notification` (Task 12).
- Produces: `notifiers.Notifier` interface (`Send(ctx context.Context, n alert.Notification) error`), `notifiers.NewWebhook(url string) *Webhook`, `notifiers.NewSlack(webhookURL string) *Slack`, `notifiers.NewTeams(webhookURL string) *Teams`, `notifiers.SendAll(ctx context.Context, ns []Notifier, n alert.Notification) []error` (one error per failing notifier; a failing notifier never stops the others). Consumed by Task 17.

- [ ] **Step 1: Write the failing tests**

```go
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
```

`notifierFunc` is a small unexported adapter type in the test file (`type notifierFunc func(context.Context, alert.Notification) error` with a `Send` method) used to build inline test doubles.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/collector/alert/notifiers/... -v`
Expected: FAIL (`Notifier`/`SendAll`/`NewWebhook` undefined)

- [ ] **Step 3: Implement the interface, `SendAll`, and the three notifiers**

`SendAll` calls every notifier's `Send` sequentially inside its own `func` so a panic-free error from one never prevents the next call, collecting non-nil errors into the returned slice. `Webhook.Send` POSTs a JSON body `{"severity": n.Severity, "source": n.Record.Source, "name": n.Record.Name, "kind": n.Record.Kind, "expires_at": n.Record.ExpiresAt}` to its configured URL. `Slack.Send` and `Teams.Send` POST to their configured incoming-webhook URL using each platform's expected JSON shape (Slack: `{"text": "..."}`; Teams: `{"text": "..."}` via a legacy MessageCard, since M1 only needs a plain text line), with the message text built from the same fields as the generic webhook — never from `n.Record.Metadata` values that could carry anything unexpected without being sanitized first.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/collector/alert/notifiers/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/collector/alert/notifiers/notifier.go internal/collector/alert/notifiers/webhook.go internal/collector/alert/notifiers/slack.go internal/collector/alert/notifiers/teams.go internal/collector/alert/notifiers/notifiers_test.go
git commit -m "feat(collector/alert/notifiers): add webhook, Slack, and Teams notifiers"
```

---

### Task 14: Email notifier

**Files:**
- Create: `internal/collector/alert/notifiers/email.go`
- Test: `internal/collector/alert/notifiers/email_test.go`

**Interfaces:**
- Consumes: `alert.Notification` (Task 12), `notifiers.Notifier` (Task 13).
- Produces: `notifiers.NewEmail(cfg EmailConfig) *Email` where `EmailConfig{SMTPHost string; SMTPPort int; From, To string}`, `(*Email) Send(ctx context.Context, n alert.Notification) error`. Consumed by Task 17.

- [ ] **Step 1: Write the failing test**

```go
func TestEmail_Send_DialsConfiguredSMTPServer(t *testing.T) {
    // A minimal local SMTP listener that accepts one message and records it,
    // enough to prove Email.Send actually attempts delivery rather than
    // silently succeeding. Any accepted sequence is fine; the point is the
    // connection and a QUIT round-trip complete without error.
    ln, err := net.Listen("tcp", "127.0.0.1:0")
    if err != nil {
        t.Fatal(err)
    }
    defer ln.Close()
    done := make(chan struct{})
    go func() {
        defer close(done)
        conn, err := ln.Accept()
        if err != nil {
            return
        }
        defer conn.Close()
        fakeSMTPServer(conn) // helper in this test file: scripted 220/250/221 responses
    }()

    host, portStr, _ := net.SplitHostPort(ln.Addr().String())
    port, _ := strconv.Atoi(portStr)
    e := NewEmail(EmailConfig{SMTPHost: host, SMTPPort: port, From: "radar@example.com", To: "oncall@example.com"})
    if err := e.Send(context.Background(), alert.Notification{Severity: "critical", Record: store.StoredRecord{ExpiryRecord: checker.ExpiryRecord{Source: "a", Name: "b"}}}); err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    <-done
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/collector/alert/notifiers/... -run TestEmail -v`
Expected: FAIL (`NewEmail` undefined)

- [ ] **Step 3: Implement `NewEmail` and `Send` in `internal/collector/alert/notifiers/email.go`**

`Send` builds a plain-text message from the same fields as the webhook notifier (severity, source, name, kind, expiry date) and sends it with `net/smtp.SendMail` against `fmt.Sprintf("%s:%d", cfg.SMTPHost, cfg.SMTPPort)`, `From: cfg.From`, `To: []string{cfg.To}`. No authentication is attempted in M1 (local/relay SMTP only); `auth smtp.Auth` is `nil`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/collector/alert/notifiers/... -run TestEmail -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/collector/alert/notifiers/email.go internal/collector/alert/notifiers/email_test.go
git commit -m "feat(collector/alert/notifiers): add SMTP email notifier"
```

---

### Task 15: JSON/CSV export

**Files:**
- Create: `internal/collector/export/export.go`
- Test: `internal/collector/export/export_test.go`

**Interfaces:**
- Consumes: `store.StoredRecord` (Task 5).
- Produces: `export.JSON(w io.Writer, records []store.StoredRecord) error`, `export.CSV(w io.Writer, records []store.StoredRecord) error`. Consumed by Task 16.

- [ ] **Step 1: Write the failing tests**

```go
func TestJSON_WritesValidArray(t *testing.T) {
    var buf bytes.Buffer
    recs := []store.StoredRecord{{ExpiryRecord: checker.ExpiryRecord{Source: "a", Name: "b", Kind: "certificate", ExpiresAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}}}
    if err := JSON(&buf, recs); err != nil {
        t.Fatal(err)
    }
    var decoded []map[string]any
    if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
        t.Fatalf("output is not valid JSON: %v", err)
    }
    if decoded[0]["source"] != "a" {
        t.Fatalf("got %+v", decoded[0])
    }
}

func TestCSV_WritesHeaderAndRow(t *testing.T) {
    var buf bytes.Buffer
    recs := []store.StoredRecord{{ExpiryRecord: checker.ExpiryRecord{Source: "a", Name: "b", Kind: "certificate", ExpiresAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}}}
    if err := CSV(&buf, recs); err != nil {
        t.Fatal(err)
    }
    reader := csv.NewReader(&buf)
    rows, err := reader.ReadAll()
    if err != nil {
        t.Fatal(err)
    }
    if len(rows) != 2 { // header + 1 data row
        t.Fatalf("got %d rows, want 2", len(rows))
    }
    if rows[0][0] != "source" {
        t.Fatalf("header = %v", rows[0])
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/collector/export/... -v`
Expected: FAIL (`JSON`/`CSV` undefined)

- [ ] **Step 3: Implement `JSON` and `CSV` in `internal/collector/export/export.go`**

`JSON` marshals `records` with `json.NewEncoder(w).Encode(records)`. `CSV` writes the header row `source,name,kind,expires_at,reported_by,checked_at` with `encoding/csv`, then one row per record with `ExpiresAt`/`CheckedAt` formatted as RFC3339.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/collector/export/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/collector/export/
git commit -m "feat(collector/export): add JSON and CSV export"
```

---

### Task 16: Dashboard HTTP handlers

**Files:**
- Create: `internal/collector/dashboard/handlers.go`
- Create: `internal/collector/dashboard/templates/list.html`
- Create: `internal/collector/dashboard/templates/history.html`
- Test: `internal/collector/dashboard/handlers_test.go`

**Interfaces:**
- Consumes: `store.Store` (Task 5), `rules.Store` (Task 6), `export.JSON`/`export.CSV` (Task 15).
- Produces: `dashboard.NewMux(st store.Store, rs rules.Store) *http.ServeMux` registering: `GET /` (list view, embeds mute/owner state per record), `GET /history?source=&name=&kind=` (history view), `POST /rules` (form fields `source`, `name`, `kind`, `muted`, `owner` → `rs.Upsert`), `GET /export.json`, `GET /export.csv`. Consumed by Task 17.

- [ ] **Step 1: Write the failing tests**

```go
func TestMux_List_Returns200WithRecords(t *testing.T) {
    st := &fakeStore{current: []store.StoredRecord{{ExpiryRecord: checker.ExpiryRecord{Source: "a", Name: "b", Kind: "certificate", ExpiresAt: time.Now().Add(48 * time.Hour)}}}}
    mux := NewMux(st, &fakeRulesStore{})
    req := httptest.NewRequest("GET", "/", nil)
    rec := httptest.NewRecorder()
    mux.ServeHTTP(rec, req)
    if rec.Code != http.StatusOK {
        t.Fatalf("got %d", rec.Code)
    }
    if !strings.Contains(rec.Body.String(), "b") {
        t.Fatal("expected record name in rendered page")
    }
}

func TestMux_PostRules_UpsertsAndRedirects(t *testing.T) {
    rs := &fakeRulesStore{}
    mux := NewMux(&fakeStore{}, rs)
    form := url.Values{"source": {"a"}, "name": {"b"}, "kind": {"certificate"}, "muted": {"on"}, "owner": {"joao"}}
    req := httptest.NewRequest("POST", "/rules", strings.NewReader(form.Encode()))
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    rec := httptest.NewRecorder()
    mux.ServeHTTP(rec, req)
    if rec.Code != http.StatusSeeOther {
        t.Fatalf("got %d, want 303", rec.Code)
    }
    if !rs.upserted.Muted || rs.upserted.Owner != "joao" {
        t.Fatalf("got %+v", rs.upserted)
    }
}

func TestMux_ExportJSON_ReturnsValidArray(t *testing.T) {
    st := &fakeStore{current: []store.StoredRecord{{ExpiryRecord: checker.ExpiryRecord{Source: "a", Name: "b", Kind: "certificate", ExpiresAt: time.Now()}}}}
    mux := NewMux(st, &fakeRulesStore{})
    req := httptest.NewRequest("GET", "/export.json", nil)
    rec := httptest.NewRecorder()
    mux.ServeHTTP(rec, req)
    var decoded []map[string]any
    if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
        t.Fatalf("not valid JSON: %v", err)
    }
}
```

`fakeStore` and `fakeRulesStore` are test doubles local to this package's test file, structurally the same shape as Task 12's but implementing the full `store.Store`/`rules.Store` interfaces (needed here since the handlers call more methods, e.g. `History`).

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/collector/dashboard/... -v`
Expected: FAIL (`NewMux` undefined)

- [ ] **Step 3: Implement `NewMux` and the handlers in `internal/collector/dashboard/handlers.go`**

Embed the two templates with `//go:embed templates/*.html`. `GET /`: call `st.ListCurrent(ctx)`, for each record call `rs.Get(ctx, ...)` to attach muted/owner state, render `list.html`. `GET /history`: call `st.History(ctx, source, name, kind)` from query params, render `history.html`. `POST /rules`: parse the form, build a `rules.Rule{Muted: r.FormValue("muted") == "on", ...}`, call `rs.Upsert`, respond `303` redirecting to `/`. `GET /export.json` / `GET /export.csv`: call `st.ListCurrent(ctx)` then `export.JSON`/`export.CSV` to the response writer with the matching `Content-Type`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/collector/dashboard/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/collector/dashboard/
git commit -m "feat(collector/dashboard): add list/history views, mute/assign-owner, and export endpoints"
```

---

### Task 17: `cmd/collector` main

**Files:**
- Create: `cmd/collector/main.go`
- Test: `cmd/collector/main_test.go`

**Interfaces:**
- Consumes: everything from Tasks 2, 4, 5, 6, 7, 8, 12, 13, 14, 16.
- Produces: the `collector` binary; an exported `run(cfg Config) error` (so the test can invoke the wiring without `os.Exit`), where `Config{DBPath, ListenAddr, AuthTokens []string; AlertInterval time.Duration; WebhookURL, SlackWebhookURL, TeamsWebhookURL string; Email notifiers.EmailConfig; TLSCertFile, TLSKeyFile string}` loaded from a JSON config file path given as the binary's only CLI argument.

- [ ] **Step 1: Write the failing test**

```go
func TestRun_ServesIngestAndDashboardOverHTTPS(t *testing.T) {
    dir := t.TempDir()
    certFile, keyFile := writeSelfSignedCertForTest(t, dir) // test helper: generates a short-lived self-signed cert/key pair to disk
    cfg := Config{
        DBPath: filepath.Join(dir, "radar.db"),
        ListenAddr: "127.0.0.1:0", // run() must report the actual bound port, e.g. via a channel/field for the test to use
        AuthTokens: []string{"test-token"},
        TLSCertFile: certFile,
        TLSKeyFile: keyFile,
    }
    addr, stop, err := startForTest(cfg) // small test-only helper in main_test.go wrapping run() to return the bound address and a shutdown func
    if err != nil {
        t.Fatal(err)
    }
    defer stop()

    client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
    batch := checker.Batch{AgentID: "agent-1", Results: []checker.Result{{CheckerName: "tls-checker", Records: []checker.ExpiryRecord{{Source: "a", Name: "b", Kind: "certificate", ExpiresAt: time.Now().Add(48 * time.Hour)}}}}}
    body, _ := json.Marshal(batch)
    req, _ := http.NewRequest("POST", "https://"+addr+"/ingest", bytes.NewReader(body))
    auth.AttachToken(req, "test-token")
    resp, err := client.Do(req)
    if err != nil || resp.StatusCode != http.StatusNoContent {
        t.Fatalf("ingest: err=%v status=%v", err, resp)
    }

    dashResp, err := client.Get("https://" + addr + "/")
    if err != nil || dashResp.StatusCode != http.StatusOK {
        t.Fatalf("dashboard: err=%v status=%v", err, dashResp)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/collector/... -v`
Expected: FAIL (`Config`/`run`/`startForTest` undefined)

- [ ] **Step 3: Implement `Config`, `run`, and `main` in `cmd/collector/main.go`**

`run(cfg)`: `db.Open(cfg.DBPath)` → `store.NewSQLite` / `rules.NewSQLite` → build the `*http.ServeMux` from `dashboard.NewMux` → register `/ingest` wrapped in `auth.Middleware(cfg.AuthTokens, ingest.Handler(st))` on the same mux → build the configured `notifiers.Notifier` slice (webhook/Slack/Teams/email, skipping any whose config field is empty) → start a goroutine that every `cfg.AlertInterval` calls `engine.Evaluate` and `notifiers.SendAll` for every non-muted, non-"ok" notification → serve with `http.ListenAndServeTLS` using `cfg.TLSCertFile`/`cfg.TLSKeyFile`. `main`: read the config file path from `os.Args[1]`, decode JSON into `Config`, call `run`, log (sanitized) and `os.Exit(1)` on error.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/collector/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cmd/collector/
git commit -m "feat(cmd/collector): wire storage, ingest, alerting, and dashboard into the collector binary"
```

---

### Task 18: `cmd/agent` main and cross-platform build

**Files:**
- Create: `cmd/agent/main.go`
- Create: `scripts/build-agent.sh`
- Test: `cmd/agent/main_test.go`

**Interfaces:**
- Consumes: `tls.New`/`tls.Target` (Task 3), `agent.NewRunner`/`NewPusher`/`NewQueue` (Tasks 9, 10, 11).
- Produces: the `agent` binary; an exported `loadConfig(path string) (Config, error)` where `Config{CollectorURL, Token, AgentID, QueuePath string; TLSTargets []tls.Target; IntervalSeconds int}` loaded from a JSON file given as the binary's only CLI argument; `scripts/build-agent.sh` cross-compiling to `dist/agent-{windows-amd64.exe, linux-amd64, linux-arm64}` covering Windows, RedHat/Debian/generic Linux (amd64) and Arch (amd64/arm64 — Arch Linux itself is the distro, not a separate `GOOS`/`GOARCH`; it is covered by the `linux-amd64`/`linux-arm64` binaries).

- [ ] **Step 1: Write the failing test**

```go
func TestLoadConfig_ParsesValidFile(t *testing.T) {
    dir := t.TempDir()
    path := filepath.Join(dir, "agent.json")
    content := `{
        "collector_url": "https://collector.example.com",
        "token": "abc",
        "agent_id": "web-01",
        "queue_path": "/var/lib/expiry-radar/queue.jsonl",
        "interval_seconds": 3600,
        "tls_targets": [{"host": "mail.example.com", "port": 25, "start_tls": "smtp"}]
    }`
    os.WriteFile(path, []byte(content), 0600)

    cfg, err := loadConfig(path)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if cfg.CollectorURL != "https://collector.example.com" || cfg.AgentID != "web-01" {
        t.Fatalf("got %+v", cfg)
    }
    if len(cfg.TLSTargets) != 1 || cfg.TLSTargets[0].StartTLS != "smtp" {
        t.Fatalf("got TLSTargets=%+v", cfg.TLSTargets)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/agent/... -v`
Expected: FAIL (`loadConfig`/`Config` undefined)

- [ ] **Step 3: Implement `Config`, `loadConfig`, `run`, and `main` in `cmd/agent/main.go`; write `scripts/build-agent.sh`**

`loadConfig` decodes the JSON file into `Config` (JSON tags `collector_url`, `token`, `agent_id`, `queue_path`, `interval_seconds`, `tls_targets`, matching `tls.Target`'s own tags `host`, `port`, `start_tls`). `main`: `loadConfig(os.Args[1])`, build `tls.New(cfg.TLSTargets)`, `agent.NewRunner(cfg.AgentID, []checker.Checker{tlsChecker}, agent.NewPusher(cfg.CollectorURL, cfg.Token), agent.NewQueue(cfg.QueuePath))`, then loop calling `runner.RunOnce(ctx)` every `cfg.IntervalSeconds` seconds (via `time.Ticker`) until the process receives `SIGINT`/`SIGTERM`.

`scripts/build-agent.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail
mkdir -p dist
GOOS=windows GOARCH=amd64 go build -o dist/agent-windows-amd64.exe ./cmd/agent
GOOS=linux   GOARCH=amd64 go build -o dist/agent-linux-amd64       ./cmd/agent
GOOS=linux   GOARCH=arm64 go build -o dist/agent-linux-arm64       ./cmd/agent
```

- [ ] **Step 4: Run test to verify it passes, then verify the cross-compilation**

Run: `go test ./cmd/agent/... -v`
Expected: PASS

Run: `bash scripts/build-agent.sh && ls dist/`
Expected: `agent-windows-amd64.exe`, `agent-linux-amd64`, `agent-linux-arm64` all present (RedHat, Debian, Arch, and generic Linux all run the `linux-amd64`/`linux-arm64` binary; there is no distro-specific build step, since the binary has no CGO dependency).

- [ ] **Step 5: Commit**

```bash
git add cmd/agent/ scripts/build-agent.sh
git commit -m "feat(cmd/agent): wire the TLS checker into the agent binary; add cross-platform build script"
```

---

### Task 19: End-to-end test

**Files:**
- Create: `test/e2e/expiry_radar_test.go`

**Interfaces:**
- Consumes: `cmd/collector`'s `run`/`Config` (Task 17) and `cmd/agent`'s `loadConfig`-equivalent wiring, exercised by starting a real Collector process in-test and driving a real `agent.Runner` against it (reusing Tasks 9, 10, 11, 3 directly, the same way `cmd/agent/main.go` does), rather than importing `cmd/agent` as a package (Go `main` packages are not importable).

- [ ] **Step 1: Write the failing end-to-end test**

```go
func TestEndToEnd_CertExpiryFlowsFromAgentToDashboard(t *testing.T) {
    dir := t.TempDir()
    certFile, keyFile := writeSelfSignedCertForTest(t, dir)
    collectorAddr, stopCollector, err := startForTest(collector.Config{
        DBPath: filepath.Join(dir, "radar.db"),
        ListenAddr: "127.0.0.1:0",
        AuthTokens: []string{"e2e-token"},
        TLSCertFile: certFile,
        TLSKeyFile: keyFile,
        AlertInterval: 100 * time.Millisecond,
    })
    if err != nil {
        t.Fatal(err)
    }
    defer stopCollector()

    // A target TLS server for the agent's checker to scan.
    targetSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
    defer targetSrv.Close()
    host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(targetSrv.URL, "https://"))
    port, _ := strconv.Atoi(portStr)

    tlsChecker := tlschecker.New([]tlschecker.Target{{Host: host, Port: port}})
    pusher := agent.NewPusher("https://"+collectorAddr, "e2e-token")
    // The Pusher's http.Client must trust the Collector's self-signed test
    // cert; set this via the same InsecureSkipVerify pattern used in Task 17's test.
    runner := agent.NewRunner("e2e-agent", []checker.Checker{tlsChecker}, pusher, agent.NewQueue(filepath.Join(dir, "queue.jsonl")))

    if err := runner.RunOnce(context.Background()); err != nil {
        t.Fatalf("RunOnce failed: %v", err)
    }

    client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
    resp, err := client.Get("https://" + collectorAddr + "/export.json")
    if err != nil {
        t.Fatal(err)
    }
    var records []map[string]any
    json.NewDecoder(resp.Body).Decode(&records)
    if len(records) != 1 {
        t.Fatalf("expected 1 exported record after the agent's push, got %d", len(records))
    }
    if records[0]["source"] != fmt.Sprintf("%s:%d", host, port) {
        t.Fatalf("got %+v", records[0])
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./test/e2e/... -v`
Expected: FAIL (compile error until the `startForTest`/`writeSelfSignedCertForTest` helpers are shared — move them from `cmd/collector/main_test.go` into an internal test-only helper file, e.g. `internal/collector/testhelpers/testhelpers.go`, exported so both test packages can import it)

- [ ] **Step 3: Factor out the shared test helpers and make the test pass**

Move `startForTest`/`writeSelfSignedCertForTest` (introduced in Task 17) into `internal/collector/testhelpers/testhelpers.go` as exported functions; update `cmd/collector/main_test.go` to import them from there instead of defining them locally.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./test/e2e/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add test/e2e/ internal/collector/testhelpers/ cmd/collector/main_test.go
git commit -m "test(e2e): verify the full agent-to-dashboard flow for the TLS checker"
```

---

## Milestone Done Criteria

M1 is complete when: `go build ./...` succeeds, `go test ./...` passes, `scripts/build-agent.sh` produces all three agent binaries, and the end-to-end test (Task 19) passes — proving an agent can check a TLS certificate, push it to a collector, and have it show up in the dashboard's export, with a muted/critical record correctly suppressed from notifications but still visible, exactly as specified.
