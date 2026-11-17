#!/usr/bin/env bash
# DAST: runs OWASP ZAP (spider + active scan) against a real collector
# with seeded data, authenticated with an admin bearer token, plus the
# unauthenticated surface (login, static files, /ingest). Ephemeral
# instance: the scan may click anything. Writes zap-report.{html,json,md}.
# Needs docker, curl, go. FAIL_ON (default: High) sets the gate level.
set -euo pipefail
W="$PWD/zap"; rm -rf "$W"; mkdir -p "$W"; chmod 777 "$W"
AGENT_TOKEN=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
ADMIN_TOKEN=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')

CGO_ENABLED=0 go build -o "$W/collector" ./cmd/collector
"$W/collector" gen-cert "$W" --host 127.0.0.1 >/dev/null
cat > "$W/collector.json" <<JSON
{"db_path":"$W/radar.db","listen_addr":"127.0.0.1:18443",
 "tls_cert_file":"$W/collector.crt","tls_key_file":"$W/collector.key",
 "auth_tokens":["$AGENT_TOKEN"],"admin_tokens":["$ADMIN_TOKEN"]}
JSON
"$W/collector" "$W/collector.json" > "$W/collector.log" 2>&1 &
trap 'kill %1 2>/dev/null || true; echo "--- collector log (tail)"; tail -20 "$W/collector.log"' EXIT
for _ in $(seq 1 30); do curl -sk -o /dev/null https://127.0.0.1:18443/login && break; sleep 1; done

# Seed records, including hostile strings, so the pages have content
# and reflected-XSS checks see attacker-controlled data.
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
curl -sfk -X POST https://127.0.0.1:18443/ingest -H "Authorization: Bearer $AGENT_TOKEN" -H 'Content-Type: application/json' -d @- <<JSON
{"agent_id":"zap-agent","results":[
 {"checker_name":"tls-checker","checked_at":"$now","records":[
  {"source":"tls://example.com:443","name":"example.com","kind":"certificate","expires_at":"2027-01-01T00:00:00Z"},
  {"source":"tls://x\"><script>alert(1)</script>:443","name":"<img src=x onerror=alert(2)>","kind":"certificate","expires_at":"2026-12-01T00:00:00Z","metadata":{"issuer":"javascript:alert(3)"}}]},
 {"checker_name":"aws","checked_at":"$now","error":"AccessDenied <b>bold</b>","records":[]}]}
JSON

# ZAP reads these to add the header to every request to the site.
docker run --rm --network host -v "$W:/zap/wrk:rw" \
  -e ZAP_AUTH_HEADER=Authorization -e ZAP_AUTH_HEADER_VALUE="Bearer $ADMIN_TOKEN" -e ZAP_AUTH_HEADER_SITE=127.0.0.1 \
  ghcr.io/zaproxy/zaproxy:stable zap-full-scan.py -t https://127.0.0.1:18443/ \
  -m 3 -T 25 -I -j -r zap-report.html -J zap-report.json -w zap-report.md || true

test -s "$W/zap-report.json" || { echo "ZAP produced no report"; exit 1; }
echo "--- ZAP alerts (risk: name, count)"
jq -r '.site[].alerts[] | "\(.riskdesc | split(" ")[0]): \(.name) [\(.cweid)] x\(.count)"' "$W/zap-report.json" | sort | uniq
level="${FAIL_ON:-High}"
bad=$(jq --arg l "$level" '[.site[].alerts[] | select((.riskdesc | split(" ")[0]) as $r | ($l=="High" and $r=="High") or ($l=="Medium" and ($r=="High" or $r=="Medium")))] | length' "$W/zap-report.json")
echo "alerts at or above $level: $bad"
[ "$bad" = 0 ]
