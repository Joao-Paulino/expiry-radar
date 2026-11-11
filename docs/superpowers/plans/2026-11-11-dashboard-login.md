# Dashboard Login Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Browser login for a single local Administrator (password + TOTP) with server-side sessions and CSRF, keeping admin bearer tokens for scripts. Closes #1.

**Architecture:** `internal/collector/admin` owns credentials (PBKDF2 password hash, TOTP, recovery codes, lockout) in SQLite. `internal/collector/session` owns sessions, the cookie, CSRF and an auth middleware accepting a session or a bearer token. The dashboard gains `/login` and `/logout`; `cmd/collector` gains two subcommands.

**Tech Stack:** Go 1.24 stdlib only (`crypto/pbkdf2`, `crypto/hmac`, `crypto/sha1`, `crypto/sha256`, `crypto/rand`, `crypto/subtle`, `encoding/base32`), existing ncruces SQLite.

**Spec:** `docs/superpowers/specs/2026-11-11-dashboard-login-design.md`

## Global Constraints

- No new module dependencies (no `golang.org/x/...`).
- PBKDF2-HMAC-SHA256, 600000 iterations, 16-byte salt, 32-byte key; encoded `pbkdf2-sha256$600000$<salt b64 raw std>$<key b64 raw std>`.
- Password minimum length: 12 characters.
- TOTP: SHA-1, 6 digits, 30 s step, accept steps `now-1..now+1`, reject step `<= totp_last_step`; secret 20 random bytes, base32 without padding.
- Recovery codes: 8 codes, 10 chars each from `abcdefghjkmnpqrstuvwxyz23456789`, stored as SHA-256 hex.
- Lockout: 5 consecutive failures → locked 15 minutes.
- Session: 32 random bytes base64url (raw); stored as SHA-256 hex; cookie `__Host-er_session`, `Path=/`, `Secure`, `HttpOnly`, `SameSite=Strict`; idle 30 min, absolute 8 h.
- CSRF token: 32 random bytes base64url, form field `csrf_token`.
- After login always redirect to `/` (never to a user-supplied URL).
- Logs never contain password, code, recovery code, session id or CSRF token.
- Local verification in this sandbox: `GOPROXY=direct GOSUMDB=off go test ./...` (gitignored `go.work` maps `golang.org/x/sys` to its GitHub mirror). CI on GitHub is authoritative.

## Review Focus

1. Session fixation: a session id existing before login must never become authenticated; login always issues a fresh id.
2. Concurrent failed logins: the failure counter must be incremented atomically in SQL, so parallel guesses cannot exceed 5 before lockout.
3. Locked account timing: a locked login still runs the password hash, so response time does not reveal lock state or password validity.
4. CSRF on every session-authenticated POST, including `/logout` and `/rules`; GET never changes state.
5. TOTP replay: a code accepted at step N is rejected for N and N-1 even though both are inside the ±1 window.

---

### Task 1: Password hashing

**Files:** Create `internal/collector/admin/password.go`, Test `internal/collector/admin/password_test.go`

**Interfaces:**
- Produces: `HashPassword(password string) (string, error)`, `VerifyPassword(encoded, password string) (bool, error)`, `const MinPasswordLength = 12`, `var ErrPasswordTooShort`.

- [ ] **Step 1: Write failing tests**: `TestHashPassword_VerifyRoundTrip` (hash "correct horse battery", verify true, verify "wrong" false); `TestHashPassword_UsesRandomSalt` (two hashes of the same password differ); `TestHashPassword_EncodedFormat` (prefix `pbkdf2-sha256$600000$`, 4 `$`-separated parts); `TestHashPassword_RejectsShort` (11 chars → `ErrPasswordTooShort`); `TestVerifyPassword_RejectsMalformed` (`"garbage"` → error).
- [ ] **Step 2: Run** `GOPROXY=direct GOSUMDB=off go test ./internal/collector/admin/ -run Password`. Expected: FAIL (undefined).
- [ ] **Step 3: Implement** with `pbkdf2.Key(sha256.New, password, salt, iterations, 32)`; verify parses the iteration count from the encoding and compares with `subtle.ConstantTimeCompare`.
- [ ] **Step 4: Run** same command. Expected: PASS.
- [ ] **Step 5: Commit** `feat(admin): PBKDF2 password hashing`.

### Task 2: TOTP and recovery codes

**Files:** Create `internal/collector/admin/totp.go`, `internal/collector/admin/recovery.go`, tests alongside.

**Interfaces:**
- Produces: `NewTOTPSecret() (string, error)`; `TOTPCode(secret string, step int64) (string, error)`; `VerifyTOTP(secret, code string, now time.Time, lastStep int64) (step int64, ok bool)`; `TOTPURI(secret string) string`; `NewRecoveryCodes() (plain []string, hashes []string, err error)`; `HashRecoveryCode(code string) string`.

- [ ] **Step 1: Write failing tests**: `TestTOTPCode_RFC6238Vectors` (secret = base32 of ASCII `12345678901234567890`; steps 1 (T=59) → `287082`, 37037036 (T=1111111109) → `081804`, 37037037 (T=1111111111) → `050471`); `TestVerifyTOTP_AcceptsAdjacentSteps` (now-1, now, now+1 ok; now±2 rejected); `TestVerifyTOTP_RejectsReplay` (lastStep = current step → rejected; returns accepted step on success); `TestTOTPURI_Format` (`otpauth://totp/Expiry%20Radar:Administrator?secret=` … `&issuer=Expiry%20Radar`); `TestNewRecoveryCodes` (8 codes, length 10, alphabet only, unique, hashes = `HashRecoveryCode(code)`).
- [ ] **Step 2: Run** `... go test ./internal/collector/admin/ -run 'TOTP|Recovery'`. Expected: FAIL.
- [ ] **Step 3: Implement** HOTP per RFC 4226 (HMAC-SHA1, dynamic truncation, mod 10^6, zero-padded); codes compared with `subtle.ConstantTimeCompare`; reject codes that are not 6 digits.
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(admin): TOTP (RFC 6238) and recovery codes`.

### Task 3: Schema and admin account store

**Files:** Modify `internal/collector/db/db.go` (3 tables from spec §3); Create `internal/collector/admin/store.go`, `store_test.go`.

**Interfaces:**
- Produces: `type Account struct { PasswordHash string; TOTPSecret string; TOTPLastStep int64; FailedAttempts int; LockedUntil time.Time }`; `type Store struct{ DB *sql.DB }`; methods `Get(ctx) (Account, bool, error)`, `SetPassword(ctx, hash string) error` (upserts row 1, resets failures/lock), `SetTOTP(ctx, secret string, recoveryHashes []string) error` (replaces secret, resets last step, replaces recovery codes), `RecordFailure(ctx, now time.Time) (locked bool, err error)` (single `UPDATE … SET failed_attempts = failed_attempts + 1, locked_until = CASE WHEN failed_attempts + 1 >= 5 THEN ? ELSE locked_until END … RETURNING`), `RecordSuccess(ctx, step int64) error` (resets failures, stores last step), `UseRecoveryCode(ctx, hash string, now time.Time) (bool, error)` (`UPDATE … WHERE code_hash = ? AND used_at IS NULL`, true if 1 row).

- [ ] **Step 1: Failing tests** with a temp DB via `db.Open`: get on empty DB → not found; `SetPassword` then `Get`; `SetTOTP` stores secret and 8 codes; `RecordFailure` ×5 → 5th returns locked and `LockedUntil ≈ now+15m`; `RecordSuccess` resets; `UseRecoveryCode` true once, false twice; `TestStore_RecordFailure_ConcurrentIsAtomic` (20 goroutines → `FailedAttempts == 20`).
- [ ] **Step 2: Run** `... go test ./internal/collector/admin/ ./internal/collector/db/`. Expected: FAIL.
- [ ] **Step 3: Implement.** (SQLite ≥ 3.35 supports `RETURNING`.)
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(admin): account store with atomic lockout`.

### Task 4: Login authenticator

**Files:** Create `internal/collector/admin/login.go`, `login_test.go`.

**Interfaces:**
- Consumes: Tasks 1–3.
- Produces: `var ErrInvalidCredentials, ErrLocked, ErrNotConfigured`; `type Authenticator struct { Store *Store; Now func() time.Time }`; `(*Authenticator) Login(ctx, password, code string) error`. Code is a 6-digit TOTP or a recovery code.

- [ ] **Step 1: Failing tests**: not configured (no password, or password but no TOTP) → `ErrNotConfigured`; correct password + current TOTP → nil; wrong password → `ErrInvalidCredentials` and failure recorded; correct password + wrong code → `ErrInvalidCredentials`; recovery code works once; same TOTP code twice → second fails; 5 failures then correct credentials → `ErrLocked`; after `Now` advances 15 min → success; `TestLogin_LockedStillHashesPassword` (inject a counter via an unexported hook `verifyPassword` var, assert it ran while locked).
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement**: always run `VerifyPassword` first (against a fixed dummy hash when not configured), then check lock, then code; on any failure `RecordFailure`.
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(admin): login with lockout and replay protection`.

### Task 5: Session store

**Files:** Modify `internal/collector/db/db.go` only if not done in Task 3; Create `internal/collector/session/store.go`, `store_test.go`.

**Interfaces:**
- Produces: `type Session struct { CSRFToken string; CreatedAt, LastSeenAt time.Time }`; `type Store struct { DB *sql.DB; Now func() time.Time }`; `Create(ctx) (id string, s Session, err error)`; `Lookup(ctx, id string) (Session, bool, error)` (enforces idle 30m and absolute 8h, deletes expired, updates `last_seen_at`); `Delete(ctx, id string) error`; `DeleteAll(ctx) error`; `const CookieName = "__Host-er_session"`; `Cookie(id string) *http.Cookie`; `ExpiredCookie() *http.Cookie`.

- [ ] **Step 1: Failing tests**: create/lookup; DB stores only the hash (raw id not found in table); idle expiry at 31 min; absolute expiry at 8h01 despite activity; delete; delete all; cookie attributes exactly per Global Constraints.
- [ ] **Step 2–4:** run (FAIL), implement, run (PASS).
- [ ] **Step 5: Commit** `feat(session): server-side sessions`.

### Task 6: Auth middleware with CSRF

**Files:** Create `internal/collector/session/middleware.go`, `middleware_test.go`.

**Interfaces:**
- Consumes: Task 5, `auth` bearer semantics (constant-time compare).
- Produces: `Middleware(st *Store, adminTokens []string, next http.Handler) http.Handler`; `CSRFToken(ctx context.Context) string` (empty for bearer requests).

- [ ] **Step 1: Failing tests**: valid bearer → 200; valid session cookie GET → 200 and `CSRFToken(ctx)` set; no auth + `Accept: text/html` → 303 to `/login`; no auth otherwise → 401; session POST without/with wrong `csrf_token` → 403; with correct token → 200; bearer POST without CSRF → 200.
- [ ] **Step 2–4:** run (FAIL), implement, run (PASS).
- [ ] **Step 5: Commit** `feat(session): auth middleware accepting session or bearer, with CSRF`.

### Task 7: Login/logout pages and wiring

**Files:** Modify `internal/collector/dashboard/handlers.go` (`NewMux` gains CSRF field rendering via `session.CSRFToken`), `templates/list.html` (hidden `csrf_token`, logout form); Create `internal/collector/dashboard/login.go`, `templates/login.html`, `login_test.go`; Modify `internal/collector/server/server.go` (routes: `GET /login`, `POST /login` public; `POST /logout` and dashboard behind `session.Middleware`).

**Interfaces:**
- Produces: `LoginHandlers(auth *admin.Authenticator, sessions *session.Store) (get, post, logout http.Handler)`.

- [ ] **Step 1: Failing tests**: GET /login renders a form with password and code fields; POST good credentials → 303 to `/`, `Set-Cookie` with `__Host-er_session`, and a pre-existing cookie value is not reused (fixation); POST bad → 200 with one generic message, no cookie; `ErrNotConfigured` shows the same generic message; logout deletes the session and expires the cookie; list page contains the CSRF hidden field; server test: browser GET `/` unauthenticated → 303 `/login`.
- [ ] **Step 2–4:** run (FAIL), implement, run (PASS). Log `login success|failed|account locked|logout` with `r.RemoteAddr` through `logging.Sanitize`.
- [ ] **Step 5: Commit** `feat(dashboard): login and logout pages`.

### Task 8: CLI subcommands

**Files:** Modify `cmd/collector/main.go`; Create `cmd/collector/admin_cmd.go`, `admin_cmd_test.go`.

**Interfaces:**
- Produces: `runSetAdminPassword(cfgPath string, in io.Reader, out io.Writer) error`; `runSetAdminTOTP(cfgPath string, in io.Reader, out io.Writer, now func() time.Time) error`. `main` dispatches `set-admin-password <cfg>`, `set-admin-totp <cfg>`, else `<cfg>` serves.

- [ ] **Step 1: Failing tests** (temp config + DB, `strings.Reader` input): password set when both entries match; mismatch → error, nothing stored; too short → error; TOTP command prints a base32 secret and `otpauth://` URI, accepts a correct code computed with `admin.TOTPCode`, stores it, prints 8 recovery codes; wrong code → error, nothing stored; both commands revoke all sessions.
- [ ] **Step 2–4:** run (FAIL), implement, run (PASS). No-echo: when stdin is a terminal on Unix, wrap reads with `stty -echo` / `stty echo` via `os/exec`; otherwise read lines as is (Ruling-worthy: stdlib only, no `x/term`).
- [ ] **Step 5: Commit** `feat(cmd/collector): set-admin-password and set-admin-totp`.

### Task 9: End-to-end test and docs

**Files:** Modify `test/e2e/expiry_radar_test.go` (new test), `README.md` (login section, EN/PT, `qrencode` tip), close #1 in the commit message.

- [ ] **Step 1: Failing test** `TestEndToEnd_AdminLoginMuteLogout`: set password and TOTP through `admin.Store`, start collector, cookie-jar client: GET `/` → login page; POST login → list; POST `/rules` with CSRF mutes a record; POST `/logout`; GET `/` → login page again.
- [ ] **Step 2–4:** run (FAIL), implement any missing wiring, run (PASS).
- [ ] **Step 5:** full suite `GOPROXY=direct GOSUMDB=off go test ./...` PASS; push; CI green on all 3 OS.
- [ ] **Step 6: Commit** `test(e2e): admin login flow; docs: dashboard login` with `Closes #1`.
