# Azure step 1 (auth + Key Vault) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** agent checks Azure Key Vault certificates, secrets and keys with an expiry date, authenticating with managed identity, certificate or workload identity.
**Architecture:** new package `internal/checker/azure` (stdlib HTTP, like `internal/checker/vault`): `config.go`, `auth.go` (three token sources + cache), `keyvault.go` (ARM discovery + data plane listing); wired in `cmd/agent`.
**Tech Stack:** Go stdlib (`crypto/rsa` PS256, `net/http`, `httptest`).
**Spec:** docs/superpowers/specs/2026-11-11-azure-keyvault-design.md

## Global Constraints
- No new module dependencies (release gate; go.mod unchanged).
- Never call an endpoint that returns secret values (`GET /secrets/<name>` without list, `/keys/<name>/...` operations); only list endpoints and the token endpoints.
- Test-only hooks: endpoint base URLs and `http.Client` overridable from tests only (unexported fields).
- README bilingual EN/PT (PT-PT), emoji headings, as the Vault section.

## Review Focus
1. Arc challenge realm outside the token directory, with `..`, not ending in `.key`, or >4 KiB → refused, file not read.
2. Token cache: a token expiring within 5 min is refreshed; concurrent vault checks share one token request.
3. Key Vault `nextLink` pointing to another host → refused (token must not leak off `*.vault.azure.net` / `management.azure.com`).
4. Vault name collision between `key_vaults` and discovery (case-insensitive) → checked once, discovery metadata kept.
5. Missing env defaults for workload identity (no `AZURE_FEDERATED_TOKEN_FILE`) → validation error naming the field.

### Task 1: config and validation — `internal/checker/azure/config.go`
- Produces: `type Config struct{ TenantID, ClientID, Auth, CertificateFile, TokenFile string; KeyVaults, Subscriptions []string }` (json names as spec), `func (c *Config) Validate() error` (applies env defaults first).
- [ ] Tests `TestConfig_Validate` (table: each auth valid; unknown auth; certificate without file; workload identity without token file nor env; bad vault name; bad subscription GUID; neither vaults nor subscriptions) → RED → implement → GREEN → commit.

### Task 2: token sources and cache — `auth.go`
- Produces: `type tokenSource interface{ token(ctx, resource string) (string, error) }`; `newTokenSource(cfg Config, hc *http.Client) (tokenSource, error)`; cache wrapper.
- [ ] `TestManagedIdentity_IMDS` (Metadata header, resource, optional client_id), `TestManagedIdentity_AppService` (X-IDENTITY-HEADER), `TestManagedIdentity_Arc` (challenge accepted inside dir; refused for realm outside dir / `..` / wrong suffix / >4 KiB).
- [ ] `TestCertificateAssertion` (fake token endpoint verifies PS256 signature with the cert's public key, `x5t#S256`, aud, iss/sub, exp−nbf ≤ 10 min).
- [ ] `TestWorkloadIdentity` (assertion = file content, re-read every request; env defaults).
- [ ] `TestTokenCache` (reuse; refresh when < 5 min left; one request under concurrency).
- RED → implement → GREEN → commit per source.

### Task 3: Key Vault and discovery — `keyvault.go`, `checker.go`
- Consumes: Task 2 `tokenSource`. Produces: `New(cfg Config) *Checker` implementing `checker.Checker` (Name `azure`).
- [ ] `TestCheck_KeyVaultItems` (certs/secrets/keys with exp → kinds; no exp, disabled, managed skipped; pagination; only list endpoints requested).
- [ ] `TestCheck_Discovery` (ARM pages, metadata location/resource_group/subscription, dedupe with `key_vaults` case-insensitive).
- [ ] `TestCheck_FailingVaultDoesNotHideOthers`, `TestCheck_AuthFailureIsError`, `TestCheck_NextLinkOtherHostRefused`.
- RED → implement → GREEN → commit.

### Task 4: wiring, README, CI
- [ ] `cmd/agent`: `Azure *azure.Config json:"azure"`, validate, add checker; test that config with `azure` yields the checker.
- [ ] README section 🔷 Azure Key Vault: config, three auth set-ups (`az` commands), roles, private endpoint/firewall notes.
- [ ] `vault_integration`-style `azure_integration_test.go` (build tag `integration`, env `AZURE_TEST_*`); CI job `azure` (`if: vars.AZURE_TEST_CLIENT_ID != ''`, `id-token: write`, fetch OIDC token with audience `api://AzureADTokenExchange`).
- [ ] Full suite, vet, govulncheck; PR.
