#!/bin/bash

# Script to run the WAF API server with MaxMind GeoIP support

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "[INFO] This script requires sudo to run"
    sudo "$0" "$@"
    exit $?
fi

# Create bin directory if it doesn't exist
mkdir -p ./bin

# If an api/.env file exists, load it into the environment for development convenience
if [[ -f "$(dirname "$0")/../api/.env" ]]; then
    echo "Loading environment variables from api/.env"
    set -a
    # shellcheck disable=SC1090
    source "$(dirname "$0")/../api/.env"
    set +a
fi

# Ensure DATABASE_URL is set (fallback to local sqlite file)
if [ -z "${DATABASE_URL:-}" ]; then
    export DATABASE_URL="./data/waf.db"
    echo "[INFO] DATABASE_URL not set, defaulting to $DATABASE_URL"
else
    echo "[INFO] Using DATABASE_URL=$DATABASE_URL"
fi

# Ensure PORT is set
if [ -z "${PORT:-}" ]; then
    export PORT=8081
fi

# Run go mod tidy to ensure dependencies are correct
echo "[INFO] Running: go mod tidy"
go mod tidy
if [ $? -ne 0 ]; then
    echo "[ERROR] go mod tidy failed!"
    exit 1
fi

# Check if binary exists, if not build it
if [ ! -f "./bin/api-server" ]; then
    echo "[INFO] Binary not found, building the server..."
    echo "[INFO] Running: (cd api && go build -o ../bin/api-server ./cmd/api-server)"
    (go build -o ../bin/api-server ./cmd/api-server)
    if [ $? -ne 0 ]; then
        echo "[ERROR] Build failed!"
        exit 1
    fi
    echo "[INFO] Build completed successfully!"
else
    echo "[INFO] Using existing binary at ./bin/api-server"
fi

# Run the server with the environment variables (DATABASE_URL, PORT, etc.)
echo "[INFO] Starting WAF API server on :${PORT} (DB: ${DATABASE_URL})"
DATABASE_URL="$DATABASE_URL" PORT="$PORT" ./bin/api-server
