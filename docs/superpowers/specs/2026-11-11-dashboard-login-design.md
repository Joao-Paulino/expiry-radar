# Expiry Radar — Dashboard Login Design (M1, issue #1)

Date: 2026-11-11
Status: Approved in conversation, pending written-spec review
Parent spec: [2026-11-10-expiry-radar-design.md](2026-11-10-expiry-radar-design.md)

## 1. Purpose

Today the dashboard, mute/assign-owner and export endpoints require
`Authorization: Bearer <admin token>`, which a browser cannot send without
an extension. This adds a browser login for a single local **Administrator**
account protected by a password **and** TOTP, while keeping bearer tokens
for scripts, and leaves a clean seam for SSO (OIDC) later.

## 2. Decisions

| Topic | Decision | Why |
|---|---|---|
| Accounts | Exactly one local Administrator | Enough until SSO; no user management |
| Setting the password | Server-side CLI command, hash stored in the DB | Password never in config, logs or shell history; needs shell access to the collector |
| MFA | TOTP (RFC 6238) required for browser login | Admin can mute alerts; ISO/IEC 27001 A.8.5 expects MFA on privileged accounts |
| Password hashing | PBKDF2-HMAC-SHA256, 600,000 iterations, 16-byte random salt (Go 1.24 `crypto/pbkdf2`) | Stdlib only, OWASP minimum, FIPS-acceptable; argon2id would need `golang.org/x/crypto` |
| Sessions | Server-side, stored hashed in SQLite | Revocable, no secrets in the cookie |
| Bearer tokens | `admin_tokens` keep working | `curl`, scripts, automation |
| SSO | Out of scope; future OIDC creates the same session | Local admin becomes break-glass |

## 3. Data model

New tables, created by the existing schema bootstrap:

- `admin_account` (single row, `id = 1`):
  `password_hash TEXT` (encoded as `pbkdf2-sha256$<iterations>$<salt b64>$<hash b64>`),
  `totp_secret TEXT` (base32, NULL until confirmed),
  `totp_last_step INTEGER` (last accepted 30 s step, for replay protection),
  `failed_attempts INTEGER`, `locked_until INTEGER` (unix seconds),
  `updated_at INTEGER`.
- `admin_recovery_codes`: `code_hash TEXT PRIMARY KEY` (SHA-256 of the code),
  `used_at INTEGER NULL`.
- `admin_sessions`: `id_hash TEXT PRIMARY KEY` (SHA-256 of the session id),
  `csrf_token TEXT`, `created_at INTEGER`, `last_seen_at INTEGER`.

## 4. CLI

The collector binary gains subcommands; the existing form
`collector <config.json>` keeps meaning "serve".

- `collector set-admin-password <config.json>`: prompts twice without echo,
  requires at least 12 characters, stores the hash, clears the lockout and
  revokes all sessions.
- `collector set-admin-totp <config.json>`: generates a 20-byte secret, prints
  the base32 key and the `otpauth://totp/Expiry%20Radar:Administrator?secret=…&issuer=Expiry%20Radar`
  URI, asks for a current code, and only on success stores the secret,
  generates 8 single-use recovery codes (printed once, stored hashed) and
  revokes all sessions. The README shows `qrencode -t ansiutf8 '<uri>'` for
  a terminal QR code.

Both commands operate on `db_path` from the config file and never start
the HTTP server.

## 5. Login flow

- `GET /login`: form with password and code fields (code accepts a 6-digit
  TOTP or a recovery code). Public route.
- `POST /login`: rejected unless both a password and a confirmed TOTP secret
  exist. On success: create a session, set the cookie, redirect to `/`.
  On failure: the same generic message for every cause, and a log line.
- `POST /logout`: deletes the session server-side and clears the cookie.
- Every dashboard route accepts **either** a valid session **or** a valid
  admin bearer token. Without either, browser requests (Accept: text/html)
  are redirected to `/login`; others get 401.
- `/ingest` is unchanged (agent tokens only).

## 6. Sessions and CSRF

- Session id: 32 random bytes, base64url; only its SHA-256 is stored.
- Cookie `__Host-er_session`: `Path=/`, `Secure`, `HttpOnly`,
  `SameSite=Strict`, no `Domain`.
- Idle timeout 30 minutes, absolute lifetime 8 hours, both enforced
  server-side; expired rows are deleted on access.
- Each session has a random CSRF token, embedded as a hidden field in every
  form; state-changing requests authenticated by session must present it
  (constant-time compare). Bearer-token requests do not need it.

## 7. Brute-force and replay protection

- After 5 consecutive failed logins the account is locked for 15 minutes;
  a successful login resets the counter. Lockout is stored in the DB, so it
  survives restarts.
- TOTP accepts the current step ±1 (30 s each) and rejects any step at or
  below `totp_last_step`.
- Recovery codes are single use.
- Password and code checks use constant-time comparison; the password hash
  is always computed, even when the account is locked, to avoid timing
  differences.
- Log lines: `login success`, `login failed`, `account locked`, `logout`,
  each with the client IP and never the password, code or session id.

## 8. Code layout

- `internal/collector/admin/`: password hashing, TOTP, recovery codes,
  account store (SQLite).
- `internal/collector/session/`: session store, cookie handling, CSRF,
  and the auth middleware that accepts a session or a bearer token.
- `internal/collector/dashboard/`: login/logout handlers and template, CSRF
  field in existing forms.
- `cmd/collector`: subcommand dispatch.

The middleware depends on a small interface (`authenticated(r) bool` style),
so a future OIDC handler only needs to create a session through the same
session store.

## 9. Testing

Unit tests, each written to fail first:

- PBKDF2 hash/verify round trip; wrong password rejected; encoded format parsed.
- TOTP matches RFC 6238 test vectors; ±1 step accepted; ±2 rejected;
  replayed step rejected.
- Recovery code works once, then is rejected.
- Login refused while password or TOTP is not set up.
- 5 failures lock the account; the 6th attempt with correct credentials is
  rejected until `locked_until`; success resets the counter.
- Session cookie attributes; idle and absolute expiry; logout revokes.
- POST without/with wrong CSRF token rejected when using a session; accepted
  with a bearer token.
- Unauthenticated browser request redirected to `/login`; API request 401.
- End-to-end: set password + TOTP through the admin package, log in over
  HTTPS, mute a record with CSRF, log out.

## 10. Out of scope

SSO/OIDC, multiple users or roles, password reset by email, WebAuthn.
