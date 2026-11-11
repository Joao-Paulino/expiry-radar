# Azure checker, step 1: authentication and Key Vault (M3)

Date: 2026-11-11 · Status: approved in conversation, spec under review · Parent: [design spec](2026-11-10-expiry-radar-design.md) M3

M3 order (agreed): **1. Key Vault + authentication** → 2. App Registration credentials (Graph) → 3. managed certificates (App Service, Front Door, Application Gateway). This spec covers step 1.

## Decisions
- **Client:** Entra ID, ARM and Key Vault REST APIs with the Go standard library (no Azure SDK: dozens of dependencies, each one CVE surface for the release gate). 15 s timeout, public cloud only (Government/China later).
- **One tenant per agent.** Several tenants = several agents.
- **Auth, exactly one of three, no stored secrets:**
  - `managed_identity`: detected from the environment. App Service / Container Apps: `IDENTITY_ENDPOINT` + `IDENTITY_HEADER` (api-version 2019-08-01, header `X-IDENTITY-HEADER`). Azure Arc: `IDENTITY_ENDPOINT` + `IMDS_ENDPOINT` without `IDENTITY_HEADER` (api-version 2020-06-01; 401 challenge `WWW-Authenticate: Basic realm=<key file>`; the key file is read only if it lies in the Arc token directory — `/var/opt/azcmagent/tokens` or `%ProgramData%\AzureConnectedMachineAgent\Tokens` — ends in `.key` and is at most 4 KiB, then sent as `Authorization: Basic <content>`). Otherwise IMDS `http://169.254.169.254/metadata/identity/oauth2/token` (api-version 2018-02-01, header `Metadata: true`). Optional `client_id` selects a user-assigned identity.
  - `certificate`: client credentials with a JWT client assertion signed by the PEM's RSA key (PS256; header `x5t#S256` = base64url SHA-256 of the certificate DER; claims `aud` = token endpoint, `iss` = `sub` = client_id, `jti`, `nbf`, `exp` = now + 10 min). The key never leaves the agent.
  - `workload_identity`: client credentials with the federated token read from `token_file` (default `AZURE_FEDERATED_TOKEN_FILE`) as the assertion. `tenant_id` / `client_id` default to `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` (as injected by AKS).
  - Token endpoint `https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token`, scopes `https://vault.azure.net/.default` and `https://management.azure.com/.default`. One token per resource, cached until 5 min before expiry.
- **Which vaults:** `key_vaults` (names; least privilege: *Key Vault Reader* on each) and/or `subscriptions` (discovery via ARM `GET /subscriptions/<id>/resources?$filter=resourceType eq 'Microsoft.KeyVault/vaults'`, needs *Reader* on the subscription; finds new vaults automatically). Both may be set; duplicates are checked once.
- **What is reported** per vault (data plane api-version 7.5, `nextLink` pagination), current versions only, items with an `exp` attribute only:
  - certificates → kind `certificate`; secrets → kind `secret`; keys → kind `key`;
  - name = item name; source `azure://<vault>.vault.azure.net`; metadata `vault` (list endpoints return no version), plus `location`, `resource_group`, `subscription` when the vault was discovered via ARM (shown on the dashboard and in CSV);
  - skipped: disabled items; secrets and keys with `managed: true` (the ones Key Vault creates behind each certificate; otherwise each certificate would appear three times).
  - Never reads values: list endpoints return attributes only.
- **Regions and networks:** discovery lists every vault in a subscription whatever its region, and the data plane address is global, so one agent covers all regions. What limits is the network: a vault with public access disabled (private endpoint) or a firewall must be reachable from the agent (VNet + `privatelink.vaultcore.azure.net` DNS, or an allowed IP); otherwise it is that vault's error and the others still count. README explains the typical errors (403 `ForbiddenByFirewall`, DNS) and the one-agent-per-VNet/hub pattern.
- **Errors:** a failing vault or subscription does not hide the others (records + joined error, as Vault and TLS do). An authentication failure is the checker's error, so the existing failing-checker alert fires.
- **Validation:** `tenant_id`/`client_id` required for `certificate`/`workload_identity` (after env defaults); vault names `^[A-Za-z][A-Za-z0-9-]{1,22}[A-Za-z0-9]$`; subscription IDs are GUIDs; at least one of `key_vaults`/`subscriptions`.

## Agent configuration
```json
"azure": {
  "tenant_id": "…",
  "client_id": "…",
  "auth": "managed_identity",
  "certificate_file": "/etc/expiry-radar/azure-sp.pem",
  "token_file": "",
  "key_vaults": ["kv-prod-weu"],
  "subscriptions": []
}
```

## Tests
- Unit: fake Entra token endpoint (checks the assertion: signature, `x5t#S256`, `aud`, lifetime), fake IMDS / App Service / Arc endpoints (incl. an Arc realm outside the token directory being refused), fake ARM and Key Vault (pagination, managed and disabled items, items without `exp`, a failing vault). Only list endpoints may be requested.
- CI against real Azure (optional job, runs only when repository variables `AZURE_TEST_TENANT_ID`, `AZURE_TEST_CLIENT_ID`, `AZURE_TEST_VAULT` are set): GitHub Actions itself is the **workload identity** (federated credential on an App Registration, no stored secret); the job fetches its OIDC token with audience `api://AzureADTokenExchange`, writes it to a file and runs the integration test against a test vault holding a certificate, a secret and a key with expiry dates. README gives the `az` commands to set it up.

## Plan (TDD)
1. `internal/checker/azure`: config + validation, the three token sources, token cache.
2. Key Vault: list certificates/secrets/keys, filters, pagination; ARM discovery; partial failures.
3. Agent wiring; README (config, roles, set-up for each auth); optional CI job with real Azure.
