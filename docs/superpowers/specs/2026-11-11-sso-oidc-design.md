# SSO via OIDC (M1, issue #7)

Date: 2026-11-11 · Status: approved in conversation · Builds on: [dashboard login](2026-11-11-dashboard-login-design.md)

## Decisions

| Topic | Decision |
|---|---|
| Providers | Several at once, any OIDC provider; one login button each |
| Who may log in | Allow-list of **verified** emails, OR membership of an Entra group (`groups` claim), OR an Entra app role (`roles` claim) |
| Entra authorization | Groups/roles; Microsoft advises against authorizing on email/`preferred_username` |
| Google | Emails only (Google ID tokens carry no groups) |
| Multi-tenant issuers | Rejected (`/common`, `/organizations`, `/consumers`) |
| Library | `github.com/coreos/go-oidc/v3` + `golang.org/x/oauth2` (signature, issuer, audience, expiry checks) |
| Session | Same server-side session/cookie/CSRF as local login; SSO sessions max `sso_session_hours` (default 1) |
| Revocation | Dashboard button "Sign out all sessions"; no SCIM |
| Break-glass | Local Administrator (password + TOTP) unchanged |

## Configuration

```json
"public_url": "https://collector.example.com:8443",
"sso_session_hours": 1,
"oidc_providers": [{
  "name": "microsoft", "display_name": "Microsoft",
  "issuer": "https://login.microsoftonline.com/<tenant-id>/v2.0",
  "client_id": "...", "client_secret_file": "/etc/expiry-radar/entra.secret",
  "allowed_emails": [], "allowed_groups": ["<group object id>"], "allowed_roles": ["ExpiryRadar.Admin"]
}]
```

Validation at startup: unique names `[a-z0-9-]+`; `https` issuer and `public_url`; at least one allow rule per provider; secret file readable and non-empty; multi-tenant Entra issuers rejected.

## Flow

1. `GET /auth/<name>/login`: random `state`, `nonce` and PKCE verifier stored server-side (`sso_flows`, hashed state, 10 min, single use); redirect to the provider with S256 challenge and nonce.
2. `GET /auth/<name>/callback`: take the flow by state (unknown, expired, wrong provider or reused → refused); exchange the code with the verifier; verify the ID token (go-oidc) and its nonce; authorize the claims; create a session with the SSO lifetime; redirect to `/`.
3. Refusals show one generic message and are logged with provider, subject and reason (never tokens or codes).

Redirect URI to register with the provider: `<public_url>/auth/<name>/callback`.

## Plan (TDD, one commit per step)

1. `server.Config`: SSO fields, defaults and validation. Tests per rule.
2. `sso.Authorize(provider, claims)`: verified-email, group and role rules, case-insensitive email. Tests.
3. `sso` flow store over `sso_flows`: put, single-use take, expiry. Session store gains a per-session lifetime (`max_age_seconds`, migrated with `ALTER TABLE` on existing databases). Tests.
4. Handlers against a fake OIDC provider (`httptest`, RSA-signed ID tokens): success, wrong nonce, reused state, expired flow, unauthorized user, tampered signature, wrong audience. Login page shows one button per provider.
5. "Sign out all sessions" (POST, CSRF), README (Entra and Google set-up, limits), go.sum generated in CI (this sandbox cannot reach golang.org).

Local verification: `GOPROXY=direct GOSUMDB=off go test ./...` with the gitignored `go.work` mapping `golang.org/x/{sys,oauth2,crypto}` to their GitHub mirrors.
