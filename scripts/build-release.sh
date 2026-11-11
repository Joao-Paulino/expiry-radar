#!/usr/bin/env bash
# Builds release binaries into dist/ with SHA-256 checksums.
# Usage: scripts/build-release.sh [version]   (default: dev)
set -euo pipefail
VERSION="${1:-dev}"
LDFLAGS="-s -w -X main.version=${VERSION}"
rm -rf dist && mkdir -p dist

build() { # <cmd> <goos> <goarch>
  local ext=""; [ "$2" = "windows" ] && ext=".exe"
  CGO_ENABLED=0 GOOS="$2" GOARCH="$3" go build -trimpath -ldflags "$LDFLAGS" \
    -o "dist/expiry-radar-$1-${VERSION}-$2-$3${ext}" "./cmd/$1"
}

build collector linux amd64
build collector linux arm64
build agent linux amd64
build agent linux arm64
build agent windows amd64

(cd dist && sha256sum expiry-radar-* > SHA256SUMS)
ls -l dist
