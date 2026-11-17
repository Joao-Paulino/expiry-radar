#!/usr/bin/env bash
# DAST with OWASP ZAP against a real collector seeded with hostile data:
#   1. dashboard: spider + active scan, authenticated with an admin bearer
#      token (the unauthenticated surface, /login and /static, is crawled too)
#   2. /ingest:   active API scan driven by docs/api/ingest.openapi.yaml,
#      authenticated with an agent token
# Ephemeral instance: the scans may click anything. Reviewed false
# positives are in scripts/ci/zap-rules.tsv, each with its reason.
# Gates: no alert at or above FAIL_ON (default High) outside that list,
# and the dashboard scan must have reached authenticated pages.
# Needs docker, curl, jq, go. Reports in ./zap/.
set -euo pipefail
W="$PWD/zap"; rm -rf "$W"; mkdir -p "$W"; chmod 777 "$W"
ZAP_IMAGE="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}"
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
trap 'kill %1 2>/dev/null || true; echo "--- collector crash (if any)"; grep -m1 -A60 -E "^(fatal error|panic|runtime: )" "$W/collector.log" || true; echo "--- collector log (tail)"; tail -20 "$W/collector.log"' EXIT
for _ in $(seq 1 30); do curl -sk -o /dev/null https://127.0.0.1:18443/login && break; sleep 1; done

# Seed records with hostile strings so reflected/stored XSS checks see
# attacker-controlled data in every column.
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
curl -sfk -X POST https://127.0.0.1:18443/ingest -H "Authorization: Bearer $AGENT_TOKEN" -H 'Content-Type: application/json' -d @- <<JSON
{"agent_id":"zap-agent<svg onload=alert(4)>","results":[
 {"checker_name":"tls-checker","checked_at":"$now","records":[
  {"source":"tls://example.com:443","name":"example.com","kind":"certificate","expires_at":"2027-01-01T00:00:00Z"},
  {"source":"tls://x\"><script>alert(1)</script>:443","name":"<img src=x onerror=alert(2)>","kind":"certificate","expires_at":"2026-12-01T00:00:00Z","metadata":{"issuer":"javascript:alert(3)"}}]},
 {"checker_name":"aws","checked_at":"$now","err_msg":"AccessDenied <b>bold</b>","records":[]}]}
JSON

cp scripts/ci/zap-rules.tsv "$W/zap-rules.tsv"
cp docs/api/ingest.openapi.yaml "$W/ingest.openapi.yaml"
ignored=$(cut -f1 scripts/ci/zap-rules.tsv | jq -R . | jq -s .)

zap() { # zap <bearer token> <script> <args...>
  local token=$1; shift
  docker run --rm --network host -v "$W:/zap/wrk:rw" \
    -e ZAP_AUTH_HEADER=Authorization -e ZAP_AUTH_HEADER_VALUE="Bearer $token" -e ZAP_AUTH_HEADER_SITE=127.0.0.1 \
    "$ZAP_IMAGE" "$@" || true # exit codes reflect warnings; the gates below decide
}

zap "$ADMIN_TOKEN" zap-full-scan.py -t https://127.0.0.1:18443/ -c zap-rules.tsv -m 3 -T 25 -I -j \
  -r dashboard.html -J dashboard.json -w dashboard.md
zap "$AGENT_TOKEN" zap-api-scan.py -t /zap/wrk/ingest.openapi.yaml -f openapi -c zap-rules.tsv -T 15 -I \
  -r ingest.html -J ingest.json -w ingest.md

fail=0
for r in dashboard ingest; do
  f="$W/$r.json"
  if ! test -s "$f"; then echo "::error::ZAP produced no $r report"; fail=1; continue; fi
  echo "=== $r: alerts (risk: name [CWE] count)"
  jq -r '.site[].alerts[] | "\(.riskdesc | split(" ")[0]): \(.name) [CWE-\(.cweid)] x\(.count)"' "$f" | sort | uniq
  echo "--- $r: Medium and High outside the reviewed list"
  jq -r --argjson ig "$ignored" '.site[].alerts[] | select(.pluginid as $p | $ig | index($p) | not) | select(.riskdesc|test("^(High|Medium)")) | "== \(.name) [CWE-\(.cweid)]", (.instances[] | "  \(.method) \(.uri) param=\(.param) evidence=\(.evidence[0:120]) other=\(.otherinfo[0:200])")' "$f"
  level="${FAIL_ON:-High}"
  bad=$(jq --arg l "$level" --argjson ig "$ignored" '[.site[].alerts[] | select(.pluginid as $p | $ig | index($p) | not) | select((.riskdesc | split(" ")[0]) as $r | ($l=="High" and $r=="High") or ($l=="Medium" and ($r=="High" or $r=="Medium")))] | length' "$f")
  echo "$r: alerts at or above $level: $bad"
  [ "$bad" = 0 ] || fail=1
done

# Coverage gate: if the bearer header stopped being applied, the scan
# would only see /login and pass while testing almost nothing.
reached=$(jq -r '[.site[].alerts[].instances[].uri] | map(select(test("/history|/export\\.(csv|json)|/agents|/rules"))) | length' "$W/dashboard.json")
echo "dashboard: authenticated URLs seen in findings: $reached"
if [ "$reached" -lt 1 ]; then echo "::error::ZAP did not reach authenticated pages: authentication is not being applied"; fail=1; fi
exit $fail
