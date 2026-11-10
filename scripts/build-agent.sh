#!/usr/bin/env bash
set -euo pipefail
mkdir -p dist
GOOS=windows GOARCH=amd64 go build -o dist/agent-windows-amd64.exe ./cmd/agent
GOOS=linux   GOARCH=amd64 go build -o dist/agent-linux-amd64       ./cmd/agent
GOOS=linux   GOARCH=arm64 go build -o dist/agent-linux-arm64       ./cmd/agent
