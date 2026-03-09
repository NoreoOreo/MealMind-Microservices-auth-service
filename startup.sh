#!/usr/bin/env bash
set -euo pipefail

# Simple start script for container/local
# Ensures env defaults then runs uvicorn

: "${HOST:=0.0.0.0}"
: "${PORT:=8000}"

exec uvicorn app.main:app --host "$HOST" --port "$PORT"
