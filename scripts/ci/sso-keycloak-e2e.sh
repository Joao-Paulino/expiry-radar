#!/usr/bin/env bash
# Runs the collector's SSO end to end against a real Keycloak (TLS),
# realm test/keycloak/expiry-realm.json. Used by the CI job sso-e2e.
set -euo pipefail
work="$(mktemp -d)"
trap 'docker logs kc 2>&1 | tail -40 || true; docker rm -f kc >/dev/null 2>&1 || true' EXIT

openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=localhost \
  -addext subjectAltName=DNS:localhost -addext basicConstraints=critical,CA:FALSE \
  -keyout "$work/kc.key" -out "$work/kc.crt" 2>/dev/null
# mktemp makes the directory 0700; the container's user must traverse it
# and read the test-only key.
chmod 755 "$work"
chmod 644 "$work/kc.key" "$work/kc.crt"

docker run -d --name kc -p 8543:8443 \
  -v "$PWD/test/keycloak:/opt/keycloak/data/import:ro" -v "$work:/certs:ro" \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin-e2e \
  quay.io/keycloak/keycloak:26.0.7 start-dev --import-realm \
  --https-port=8443 --https-certificate-file=/certs/kc.crt --https-certificate-key-file=/certs/kc.key \
  --hostname=https://localhost:8543 >/dev/null

issuer=https://localhost:8543/realms/expiry
for _ in $(seq 1 90); do
  if curl -sf --cacert "$work/kc.crt" "$issuer/.well-known/openid-configuration" >/dev/null; then break; fi
  sleep 2
done
curl -sf --cacert "$work/kc.crt" "$issuer/.well-known/openid-configuration" | jq -e --arg i "$issuer" '.issuer == $i' >/dev/null

# The collector must trust Keycloak like a production install would.
cat /etc/ssl/certs/ca-certificates.crt "$work/kc.crt" > "$work/bundle.pem"
SSL_CERT_FILE="$work/bundle.pem" EXPIRY_RADAR_E2E_KEYCLOAK="$issuer" \
  go test -count=1 -run TestSSO_Keycloak -v ./internal/collector/server/
