#!/usr/bin/env bash
# Starts a real Vault (dev mode, TLS), creates a PKI mount with a renewed
# and a revoked certificate plus an AppRole limited to the policy from
# the README, a KV v2 secret with an expiry date, then runs the Vault checker against it.
set -euo pipefail
W="$PWD/out-vault"; rm -rf "$W"; mkdir -p "$W"; chmod 777 "$W"
docker run -d --name vault --network host --cap-add IPC_LOCK -v "$W:/certs" hashicorp/vault:1.17 \
  server -dev -dev-root-token-id=root -dev-tls -dev-tls-cert-dir=/certs -dev-listen-address=127.0.0.1:8200 >/dev/null
trap 'docker logs vault 2>&1 | tail -20; docker rm -f vault >/dev/null 2>&1 || true' EXIT
v() { docker exec -e VAULT_ADDR=https://127.0.0.1:8200 -e VAULT_CACERT=/certs/vault-ca.pem -e VAULT_TOKEN=root vault vault "$@"; }
for i in $(seq 1 30); do v status >/dev/null 2>&1 && break; sleep 1; done

v secrets enable pki >/dev/null
v secrets tune -max-lease-ttl=87600h pki >/dev/null
v write pki/root/generate/internal common_name="Smoke Root CA" issuer_name=smoke-root ttl=87600h >/dev/null
v write pki/roles/web allowed_domains=example.com allow_subdomains=true max_ttl=720h >/dev/null
v write pki/issue/web common_name=api.example.com ttl=24h >/dev/null
v write pki/issue/web common_name=api.example.com ttl=240h >/dev/null   # renewal: only this one may be reported
serial=$(v write -field=serial_number pki/issue/web common_name=old.example.com ttl=48h)
v write pki/revoke serial_number="$serial" >/dev/null

# KV v2 (dev mode mounts it at secret/): one secret with an expiry date
# in its metadata, one without, one in a nested folder.
v kv put secret/apps/stripe api_key=sk_test_never_read >/dev/null
v kv metadata put -custom-metadata=expires_at=2027-03-31 secret/apps/stripe >/dev/null
v kv put secret/apps/team/db password=never_read >/dev/null
v kv metadata put -custom-metadata=expires_at=2027-01-15T10:00:00Z secret/apps/team/db >/dev/null
v kv put secret/no-expiry value=x >/dev/null

docker exec -i -e VAULT_ADDR=https://127.0.0.1:8200 -e VAULT_CACERT=/certs/vault-ca.pem -e VAULT_TOKEN=root vault \
  vault policy write expiry-radar - <<'HCL' >/dev/null
path "pki/certs"    { capabilities = ["list"] }
path "pki/cert/*"   { capabilities = ["read"] }
path "pki/issuers"  { capabilities = ["list"] }
path "pki/issuer/*" { capabilities = ["read"] }
path "secret/metadata/*" { capabilities = ["list", "read"] }
HCL
v auth enable approle >/dev/null
v write auth/approle/role/expiry-radar token_policies=expiry-radar token_ttl=5m secret_id_ttl=10m >/dev/null
ROLE_ID=$(v read -field=role_id auth/approle/role/expiry-radar/role-id)
v write -f -field=secret_id auth/approle/role/expiry-radar/secret-id > "$W/secret-id"

VAULT_TEST_ADDR=https://127.0.0.1:8200 VAULT_TEST_CA="$W/vault-ca.pem" VAULT_TEST_ROLE_ID="$ROLE_ID" \
VAULT_TEST_SECRET_ID_FILE="$W/secret-id" \
  go test -count=1 -tags integration -run TestIntegration -v ./internal/checker/vault/
echo "vault smoke: OK"
