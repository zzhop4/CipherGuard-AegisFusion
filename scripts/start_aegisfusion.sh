#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT/.env"

if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
fi

APP="${CIPHERGUARD_APP:-$ROOT/runtime/cipherguard_app}"
PY="${AEGISFUSION_PYTHON:-python3}"
SERVICE="${AEGISFUSION_SERVICE_DIR:-$ROOT/services/model_runtime/aegisfusion_service}"
PORT="${AEGISFUSION_MODEL_PORT:-18083}"
LOG_DIR="$ROOT/logs"
RUN_DIR="$ROOT/run"
LOG="$LOG_DIR/aegisfusion_service.log"
PID_FILE="$RUN_DIR/aegisfusion_service.pid"

mkdir -p "$LOG_DIR" "$RUN_DIR" "$APP"

if [ -f "$PID_FILE" ]; then
  OLD="$(cat "$PID_FILE" 2>/dev/null || true)"
  if [ -n "$OLD" ] && kill -0 "$OLD" 2>/dev/null; then
    echo "AegisFusion already running: PID=$OLD"
    exit 0
  fi
fi

export CIPHERGUARD_APP="$APP"
export AEGISFUSION_PROJECT="${AEGISFUSION_PROJECT:-$ROOT/runtime/aegisfusion_project}"
export AEGISFUSION_DATA_DIR="${AEGISFUSION_DATA_DIR:-$ROOT/data/processed/tabular_v1}"
export AEGISFUSION_BASE_MODEL_DIR="${AEGISFUSION_BASE_MODEL_DIR:-$ROOT/models/hierarchical_full_v1}"
export AEGISFUSION_TEMPORAL_MODEL_DIR="${AEGISFUSION_TEMPORAL_MODEL_DIR:-$ROOT/models/temporal_infiltration_full_v1}"

nohup "$PY" -m uvicorn app:app \
  --app-dir "$SERVICE" \
  --host "${CIPHERGUARD_HOST:-0.0.0.0}" \
  --port "$PORT" \
  --workers 1 > "$LOG" 2>&1 &

PID=$!
echo "$PID" > "$PID_FILE"
sleep 2

if ! kill -0 "$PID" 2>/dev/null; then
  echo "[ERROR] AegisFusion failed to start"
  tail -n 120 "$LOG" || true
  exit 1
fi

echo "AegisFusion PID=$PID"
echo "Health: http://127.0.0.1:${PORT}/api/v1/aegisfusion/health"
