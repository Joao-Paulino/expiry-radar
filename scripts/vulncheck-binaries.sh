#!/usr/bin/env bash
# Fails if any given Go binary contains a known vulnerability (or cannot
# be scanned). Release gate and weekly audit both use it.
# Usage: scripts/vulncheck-binaries.sh <binary>...
set -uo pipefail
GOVULNCHECK="${GOVULNCHECK:-govulncheck}"
[ "$#" -gt 0 ] || { echo "no binaries given" >&2; exit 2; }
failed=0
for f in "$@"; do
  echo "== $(basename "$f") ($(go version "$f" | awk '{print $NF}'))"
  if "$GOVULNCHECK" -mode=binary "$f"; then
    echo "   OK"
  else
    echo "   FAIL: vulnerabilities found or scan error" >&2
    failed=1
  fi
done
exit "$failed"
