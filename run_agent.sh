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

# Load .env into the current shell (so the checks below work)
if [[ -f "$ROOT_DIR/.env" ]]; then
  # Export variables defined in .env (ignore commented lines)
  set -a
  # shellcheck disable=SC1091
  source "$ROOT_DIR/.env"
  set +a
  echo "[run_agent] Loaded .env"
fi

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

# Start a dedicated Chrome instance that exposes a CDP endpoint so the agent can
# attach to the active tab (used by the test extension).
#
# Note: This launches a separate profile directory to avoid interfering with the
# user's main Chrome profile.
CHROME_DEBUG_PORT="${CHROME_DEBUG_PORT:-9222}"
CHROME_PROFILE_DIR="${CHROME_PROFILE_DIR:-.chrome-agent-profile}"

if [[ "${START_CDP_CHROME:-1}" == "1" ]]; then
  if ! lsof -iTCP:"${CHROME_DEBUG_PORT}" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "[run_agent] Starting Chrome with remote debugging on port ${CHROME_DEBUG_PORT}..."
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
      --remote-debugging-port="${CHROME_DEBUG_PORT}" \
      --user-data-dir="${CHROME_PROFILE_DIR}" \
      --no-first-run \
      --no-default-browser-check \
      >/dev/null 2>&1 &
    disown || true
    sleep 1
  else
    echo "[run_agent] Chrome remote debugging already listening on port ${CHROME_DEBUG_PORT}."
  fi
fi

export CDP_ENDPOINT="http://127.0.0.1:${CHROME_DEBUG_PORT}"

echo "[run_agent] CDP endpoint: ${CDP_ENDPOINT}"

HOST="${SERVER_HOST:-0.0.0.0}"
PORT="${SERVER_PORT:-8001}"
RELOAD="${RELOAD:-true}"

echo "[run_agent] Starting API server on http://${HOST}:${PORT} (reload=${RELOAD})"

if [[ "$RELOAD" == "true" ]]; then
  exec uvicorn main:app --host "$HOST" --port "$PORT" --reload
else
  exec uvicorn main:app --host "$HOST" --port "$PORT"
fi
