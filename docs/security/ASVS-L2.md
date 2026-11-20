# OWASP ASVS 4.0.3 Level 2 self-assessment

Version assessed: v0.8.1. Numbering follows ASVS 4.0.3. Status: ✅ met, ⚠️ partial, ❌ not met, N/A not applicable.
Requirements that do not apply to a single-binary Go service with server-rendered pages (for example SOAP, GraphQL, file upload, WebSockets) are grouped as N/A per chapter. Evidence points to code, tests or the [pentest report](PENTEST-2026-11.md).

> **Update (M11, after v0.8.1):** role separation (V4.1.5, admin/operator/viewer RBAC) has since been added — see the row below and [docs/ARCHITECTURE.md §7](../ARCHITECTURE.md#roles-rbac). The rest of this assessment still reflects v0.8.1 and has not been re-run against the current codebase.
> **Atualização (M11, depois da v0.8.1):** a separação de papéis (V4.1.5, RBAC admin/operator/viewer) foi entretanto acrescentada — ver a linha abaixo e [docs/ARQUITETURA.md §7](../ARQUITETURA.md#papéis-rbac). O resto desta avaliação ainda reflete a v0.8.1 e não foi refeita sobre o código atual.

## Resumo (PT-PT)

Autoavaliação da Expiry Radar contra o OWASP ASVS 4.0.3 nível 2. Os capítulos de autenticação, sessões, controlo de acessos, validação, criptografia, erros/logs, proteção de dados, comunicações e configuração estão cumpridos. As lacunas parciais são: dependências de CI fixadas por tag e não por SHA (V14.2) e tokens partilhados ainda aceites por compatibilidade (V2.10). A separação de papéis de administrador (V4.1.5) foi resolvida no M11 (RBAC), depois desta avaliação. Não é uma certificação independente.

## V1 Architecture, design and threat modelling

| Req | Status | Evidence |
|---|---|---|
| 1.1.1 Secure SDLC | ✅ | PR-only `main`, required CI checks, independent review per PR |
| 1.1.2 Threat modelling | ✅ | `docs/ARCHITECTURE.md` §7 trust boundaries |
| 1.1.6 Centralised security controls | ✅ | one auth middleware per surface (`internal/auth`, `internal/collector/session`) |
| 1.2.1 Least-privilege service accounts | ✅ | systemd unit with dedicated user and hardening; Windows service with ACL-restricted config |
| 1.4.1 Access control enforced server-side | ✅ | all checks in Go handlers |
| 1.5.3 Input validation at a trusted layer | ✅ | ingest decode + validation server-side |
| 1.6.2 Key and secret custody | ✅ | secrets in files with 0600 / ACL; `*_file` config options |
| 1.14.6 No unsupported or deprecated client tech | ✅ | no plugins, no inline JS |

## V2 Authentication

| Req | Status | Evidence |
|---|---|---|
| 2.1.1 Passwords ≥ 12 characters | ✅ | `admin.MinPasswordLength = 12` |
| 2.1.2 Passwords ≥ 64 characters allowed | ✅ | no maximum length |
| 2.1.7 Breached password check | ❌ | not implemented (offline tool, no external calls by design) |
| 2.2.1 Anti-automation | ✅ | 5 failures per address per 15 min; lockout after 20 (ATHN-02/03/04) |
| 2.2.3 Notify on authentication changes | N/A | single local admin |
| 2.4.1 Salted, iterated password hashing | ✅ | PBKDF2-SHA256, 600 000 iterations, 16-byte random salt |
| 2.5.x Credential recovery | ✅ | one-time recovery codes, hashed; no email reset |
| 2.7/2.8 Out-of-band and TOTP | ✅ | RFC 6238 TOTP, replay protection (ATHN-01) |
| 2.9 Cryptographic verifiers | N/A | |
| 2.10.1 Service authentication not static shared secrets | ⚠️ | per-agent tokens bound to `agent_id` (BUSL-02 fix); shared `auth_tokens` still accepted with a start-up warning |
| 2.10.4 Secrets not in source code | ✅ | config files only; gosec G101 gate |

## V3 Session management

| Req | Status | Evidence |
|---|---|---|
| 3.1.1 No session token in URL | ✅ | cookie only |
| 3.2.1 New token on authentication | ✅ | SESS-01 |
| 3.2.2 ≥ 64 bits entropy | ✅ | 256 bits |
| 3.3.1 Logout invalidates server-side | ✅ | SESS-05 |
| 3.3.2 Idle / absolute timeout | ✅ | 30 min / 8 h |
| 3.4.1–3.4.5 Cookie attributes | ✅ | `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/` |
| 3.5.2 Bearer tokens for APIs | ✅ | admin and agent bearer tokens, constant-time compare |
| 3.7.1 Re-auth before sensitive actions | N/A | no account settings in the UI |

## V4 Access control

| Req | Status | Evidence |
|---|---|---|
| 4.1.1 Enforced on a trusted service layer | ✅ | |
| 4.1.3 Least privilege | ✅ | agent tokens cannot read; admin tokens cannot ingest (ATHZ-01/02) |
| 4.1.5 Fail securely | ✅ | invalid bearer → 401, never falls back (ATHZ-04) |
| 4.2.1 IDOR protection | ✅ | agent can only write as its bound id (BUSL-02) |
| 4.2.2 Anti-CSRF | ✅ | per-session token on cookie POSTs (CSRF-01/02/03) |
| 4.3.1 Admin interfaces protected by MFA | ✅ | TOTP mandatory for password login; SSO delegates MFA to the IdP |
| 4.1.5 / Role separation | ✅ (added M11, after this assessment) | admin/operator/viewer RBAC, fail-closed on unknown role; see `internal/collector/session`, `internal/collector/sso/roles.go` |

## V5 Validation, sanitisation and encoding

| Req | Status | Evidence |
|---|---|---|
| 5.1.1 HTTP parameter pollution | ✅ | single-value parsing |
| 5.1.3 Input validated (allow-list) | ✅ | agent id pattern, resource id checks, JSON schema decode |
| 5.2.x Sanitisation | ✅ | `html/template` contextual escaping |
| 5.3.1/5.3.3 Output encoding, XSS | ✅ | INPV-01, ZAP |
| 5.3.4 Parameterised queries | ✅ | INPV-02 |
| 5.3.6 Log injection | ✅ | `logging.Sanitize`, fuzzed (INPV-03) |
| 5.5.1 Safe deserialisation | ✅ | `encoding/json` into typed structs, 16 MiB limit |

## V6 Stored cryptography

| Req | Status | Evidence |
|---|---|---|
| 6.2.1 Fail securely | ✅ | |
| 6.2.2 Proven algorithms | ✅ | Go stdlib only; ECDSA P-256 for `gen-cert` |
| 6.3.1 CSPRNG | ✅ | `crypto/rand` for tokens, session ids, salts |
| 6.4.1 Secrets management | ✅ | `*_file` options, 0600 files, no secret values stored in records |

## V7 Error handling and logging

| Req | Status | Evidence |
|---|---|---|
| 7.1.1 No credentials or session ids in logs | ✅ | tokens never logged; reviewed with gosec G104/G115 |
| 7.1.3 Security events logged | ✅ | failed logins, throttling, lockout, impersonation attempts |
| 7.3.1 Log encoding | ✅ | sanitiser (5.3.6) |
| 7.4.1 Generic error messages | ✅ | ERRH-01, generic login error |

## V8 Data protection

| Req | Status | Evidence |
|---|---|---|
| 8.1.1 No sensitive data in caches | ✅ | `Cache-Control: no-store` on every response except `/static/` |
| 8.2.x Client-side storage | ✅ | only theme preference in `localStorage` |
| 8.3.1 Sensitive data not in URL | ✅ | |
| 8.3.4 Secrets never collected | ✅ | checkers record expiry metadata only, never secret values |

## V9 Communication

| Req | Status | Evidence |
|---|---|---|
| 9.1.1 TLS for all connections | ✅ | collector HTTPS only; HSTS |
| 9.1.2 Strong cipher suites | ✅ | TLS ≥ 1.2, Go defaults (CRYP-01) |
| 9.2.1 Outbound TLS verified | ✅ | `MinVersion` TLS 1.2; `insecure_skip_verify` only on explicit opt-in (CodeQL accepted) |

## V10 Malicious code

| Req | Status | Evidence |
|---|---|---|
| 10.2.1 No phone-home / data exfiltration | ✅ | only configured endpoints |
| 10.3.2 Integrity of updates | ✅ | SHA256SUMS published; installers verify checksums before installing |
| 10.3.3 Subdomain takeover | N/A | |

## V11 Business logic

| Req | Status | Evidence |
|---|---|---|
| 11.1.2 Business limits | ✅ | body limit, future `checked_at` clamped |
| 11.1.4 Anti-automation | ✅ | login throttle |
| 11.1.5 Business-logic threats considered | ✅ | BUSL-01/02 found, fixed, tested |

## V12 Files and resources

N/A for uploads. 12.3.1 path handling: config and cert paths come from the admin-owned config file only. ✅

## V13 API and web services

| Req | Status | Evidence |
|---|---|---|
| 13.1.3 No sensitive data in API URLs | ✅ | |
| 13.2.1 Methods restricted | ✅ | Go 1.22 method patterns (`POST /ingest`) |
| 13.2.5 Content-Type checked | ✅ | JSON decode, 400 on invalid |
| 13.2.6 Size limits | ✅ | 16 MiB → 413 |
| OpenAPI description | ✅ | `docs/api/ingest.openapi.yaml`, scanned by ZAP |

## V14 Configuration

| Req | Status | Evidence |
|---|---|---|
| 14.1.1 Reproducible, secure build | ✅ | CI release pipeline, `CGO_ENABLED=0`, SHA256SUMS |
| 14.2.1 Components up to date | ✅ | govulncheck gate on every release |
| 14.2.4 Third-party components from trusted sources | ⚠️ | Go modules with checksum DB; **GitHub Actions and ZAP image pinned by tag, not SHA/digest** |
| 14.2.6 Minimal dependencies | ✅ | stdlib + `x/sys`, `x/oauth2`, `modernc.org/sqlite` |
| 14.3.2 Debug off in production | ✅ | no debug endpoints |
| 14.4.x Security headers | ✅ | CSP, HSTS, nosniff, Referrer-Policy, COOP/CORP/COEP, Permissions-Policy (CONF-01) |
| 14.5.3 CORS | ✅ | no CORS headers (same-origin only) |

## Open items

1. Pin GitHub Actions to commit SHAs and the ZAP image to a digest (V14.2.4).
2. Remove shared `auth_tokens` support in a future major version (V2.10.1).
3. Optional breached-password check against a local list (V2.1.7).
