#!/usr/bin/env bash
# Runs the real agent binary inside RedHat-family, Debian and Arch
# containers against a real collector and a real STARTTLS mail server,
# then checks the collector received valid certificate records from
# each distro. Used by CI (needs docker, openssl, curl, jq, go).
set -euo pipefail
W="$PWD/out"; rm -rf "$W"; mkdir -p "$W"
AGENT_TOKEN=$(openssl rand -hex 32); ADMIN_TOKEN=$(openssl rand -hex 32)

CGO_ENABLED=0 go build -o "$W/collector" ./cmd/collector
CGO_ENABLED=0 go build -o "$W/agent" ./cmd/agent

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -sha256 -days 2 -nodes \
  -keyout "$W/tls.key" -out "$W/tls.crt" -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
chmod 644 "$W/tls.key" "$W/tls.crt"   # readable by the mailpit container user

docker run -d --name mailpit --network host -v "$W:/certs:ro" axllent/mailpit:latest \
  --smtp-tls-cert /certs/tls.crt --smtp-tls-key /certs/tls.key --smtp-require-starttls >/dev/null

cat > "$W/collector.json" <<JSON
{"db_path":"$W/radar.db","listen_addr":"127.0.0.1:8443",
 "tls_cert_file":"$W/tls.crt","tls_key_file":"$W/tls.key",
 "auth_tokens":["$AGENT_TOKEN"],"admin_tokens":["$ADMIN_TOKEN"]}
JSON
"$W/collector" "$W/collector.json" > "$W/collector.log" 2>&1 &
trap 'kill %1 2>/dev/null || true; docker rm -f mailpit >/dev/null 2>&1 || true' EXIT
for i in $(seq 1 30); do curl -sk -o /dev/null https://127.0.0.1:8443/login && break; sleep 1; done
for i in $(seq 1 30); do curl -s -o /dev/null http://127.0.0.1:8025/ && break; sleep 1; done

export_json() { curl -sk -H "Authorization: Bearer $ADMIN_TOKEN" https://127.0.0.1:8443/export.json; }

fail=0
for image in rockylinux:9 debian:12 archlinux:latest; do
  id="smoke-${image%%:*}"
  cat > "$W/$id.json" <<JSON
{"collector_url":"https://127.0.0.1:8443/ingest","collector_ca_file":"/w/tls.crt",
 "token":"$AGENT_TOKEN","agent_id":"$id","queue_path":"/tmp/queue.jsonl","interval_seconds":3600,
 "tls_targets":[{"host":"127.0.0.1","port":8443},{"host":"localhost","port":1025,"start_tls":"smtp"}]}
JSON
  echo "== $image"
  docker run --rm --network host -v "$W:/w:ro" "$image" sh -c \
    "cat /etc/os-release | head -2 && /w/agent version && (timeout 20 /w/agent /w/$id.json; true)"
  sleep 1
  # The targets use a self-signed certificate, so each record carries a
  # verify_error; what matters is that both were read and delivered.
  got=$(export_json | jq --arg id "$id" '[.[] | select(.reported_by == $id and .expires_at != null)] | length')
  echo "   records from $id: $got (want 2: HTTPS + SMTP STARTTLS)"
  [ "$got" -ge 2 ] || fail=1
done

echo "== email notifier over STARTTLS"
SMTP_TEST_ADDR=localhost:1025 SMTP_TEST_CA="$W/tls.crt" MAILPIT_API=http://127.0.0.1:8025 \
  go test -count=1 -tags integration -run TestIntegration ./internal/collector/alert/notifiers/ || fail=1

[ "$fail" = 0 ] || { echo "--- collector log"; cat "$W/collector.log"; exit 1; }
echo "distro smoke: OK"
