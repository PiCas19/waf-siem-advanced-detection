#!/usr/bin/env bash
set -euo pipefail

# Directory of this script
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Config
PORTS=(8081 8082 8083)
DB_PATH="${DATABASE_URL:-$REPO_ROOT/data/waf.db}"
LOG_DIR="$REPO_ROOT/logs"

mkdir -p "$LOG_DIR"
mkdir -p "$REPO_ROOT/data"

# Build once (faster startups). If go is not installed or build fails, fallback to go run
BIN_DIR="$REPO_ROOT/bin"
mkdir -p "$BIN_DIR"
BIN_API="$BIN_DIR/api-server"

build_api() {
  if command -v go >/dev/null 2>&1; then
    echo "Building api-server binary..."
    (cd "$REPO_ROOT" && go build -o "$BIN_API" ./api/cmd/api-server)
  else
    echo "Go toolchain not found; will use 'go run' fallback"
  fi
}

start_instance() {
  local port="$1"
  local log_file="$LOG_DIR/api-${port}.log"
  echo "Starting API on port ${port} (DB: $DB_PATH) ..."
  if [[ -x "$BIN_API" ]]; then
    (PORT="$port" DATABASE_URL="$DB_PATH" "$BIN_API" >"$log_file" 2>&1 & echo $! >"$LOG_DIR/api-${port}.pid")
  else
    (cd "$REPO_ROOT" && PORT="$port" DATABASE_URL="$DB_PATH" go run ./api/cmd/api-server >"$log_file" 2>&1 & echo $! >"$LOG_DIR/api-${port}.pid")
  fi
}

stop_all() {
  echo "Stopping all API instances..."
  for port in "${PORTS[@]}"; do
    pid_file="$LOG_DIR/api-${port}.pid"
    if [[ -f "$pid_file" ]]; then
      pid=$(cat "$pid_file" || true)
      if [[ -n "${pid}" ]] && kill -0 "$pid" 2>/dev/null; then
        kill "$pid" || true
      fi
      rm -f "$pid_file"
    fi
  done
}

case "${1:-start}" in
  start)
    build_api || true
    for p in "${PORTS[@]}"; do
      start_instance "$p"
    done
    echo "All instances started. Logs in $LOG_DIR/*.log"
    ;;
  stop)
    stop_all
    ;;
  restart)
    stop_all
    sleep 1
    "$0" start
    ;;
  *)
    echo "Usage: $0 {start|stop|restart}" >&2
    exit 1
    ;;
 esac
