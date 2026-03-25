#!/usr/bin/env bash
set -euo pipefail

: "${HOST:=0.0.0.0}"
: "${PORT:=8000}"

if command -v opentelemetry-instrument >/dev/null 2>&1; then
  exec opentelemetry-instrument uvicorn app.main:app --host "$HOST" --port "$PORT"
fi

exec uvicorn app.main:app --host "$HOST" --port "$PORT"
