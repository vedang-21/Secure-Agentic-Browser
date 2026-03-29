#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

# Ensure venv exists
if [[ ! -d "venv" ]]; then
  echo "[run_agent] venv/ not found. Creating virtual environment..."
  python3 -m venv venv
fi

# Activate venv
# shellcheck disable=SC1091
source "$ROOT_DIR/venv/bin/activate"

echo "[run_agent] Using Python: $(python -c 'import sys; print(sys.executable)')"

# Install/refresh dependencies
echo "[run_agent] Installing dependencies from config/requirements.txt ..."
python -m pip install -q --upgrade pip
python -m pip install -q -r config/requirements.txt

# Basic env guard
if [[ -z "${GOOGLE_API_KEY:-}" && -z "${GEMINI_API_KEY:-}" ]]; then
  echo "[run_agent] ERROR: Missing GOOGLE_API_KEY (recommended) or GEMINI_API_KEY."
  echo "           Set it in your shell or create a .env file in the repo root."
  exit 1
fi

HOST="${SERVER_HOST:-0.0.0.0}"
PORT="${SERVER_PORT:-8001}"
RELOAD="${RELOAD:-true}"

echo "[run_agent] Starting API server on http://${HOST}:${PORT} (reload=${RELOAD})"

if [[ "$RELOAD" == "true" ]]; then
  exec uvicorn main:app --host "$HOST" --port "$PORT" --reload
else
  exec uvicorn main:app --host "$HOST" --port "$PORT"
fi
