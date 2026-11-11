# Vault checker, step 1: PKI certificates and CAs (M2, issue #10)

Date: 2026-11-11 · Status: approved in conversation · Parent: [design spec](2026-11-10-expiry-radar-design.md) M2

## Decisions
- **Client:** Vault HTTP API with the Go standard library (no `hashicorp/vault/api`: dozens of dependencies for a few calls). 15 s timeout, optional CA file, optional namespace (`X-Vault-Namespace`).
- **Auth:** AppRole (`role_id` + `secret_id_file`; login every run, `revoke-self` at the end) or `token_file`. Exactly one. `https://` address required.
- **Least privilege:** README ships a policy with `list`/`read` on `<mount>/certs`, `<mount>/cert/*`, `<mount>/issuers`, `<mount>/issuer/*` only. Never reads secret values.
- **What is reported** per configured mount:
  - issued certificates: kind `certificate`, name = CN (serial if no CN), source `vault://<host>/<mount>`; only the **latest** certificate per name (Vault keeps renewed ones listed until tidy); revoked certificates and ones expired more than 30 days ago are skipped;
  - CA issuers: kind `ca_certificate`, name = issuer name or CN.
- **Errors:** a failing mount does not stop the others (records + error, as TLS does).

## Agent configuration
```json
"vault": {
  "address": "https://vault.example.com:8200",
  "ca_file": "/etc/expiry-radar/vault-ca.pem",
  "namespace": "",
  "auth": { "approle": { "role_id": "…", "secret_id_file": "/etc/expiry-radar/vault-secret-id" } },
  "pki_mounts": ["pki", "pki_int"]
}
```

## Plan (TDD)
1. `internal/checker/vault`: `Config.Validate`, client (AppRole login, token file, namespace header, revoke-self). Tests against a fake Vault.
2. PKI checker: latest-per-name, revoked/old skipped, issuers, partial failure, only allowed paths requested. Tests against the fake Vault.
3. Agent wiring and validation; README (config, policy, AppRole set-up); CI smoke against a real Vault dev server (`hashicorp/vault`) with a PKI mount.
