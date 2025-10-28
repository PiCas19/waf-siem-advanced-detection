#!/bin/bash

# Script to run the WAF API server with MaxMind GeoIP support

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "[INFO] This script requires sudo to run"
    sudo "$0" "$@"
    exit $?
fi

# Check if MAXMIND_LICENSE_KEY is set
if [ -z "$MAXMIND_LICENSE_KEY" ]; then
    echo "[INFO] MaxMind GeoIP License Key not set"
    echo ""
    read -p "Enter your MaxMind License Key (or press Enter to skip): " license_key

    if [ -z "$license_key" ]; then
        echo "[WARN] No license key provided"
        echo "[INFO] Proceeding without MaxMind (will use fallback IP ranges)..."
    else
        export MAXMIND_LICENSE_KEY="$license_key"
        echo "[INFO] License key set successfully"
    fi
fi

# Check if binary exists
if [ ! -f "./bin/api-server" ]; then
    echo "[ERROR] Binary not found at ./bin/api-server"
    echo "[INFO] Please build it first with: go build -o bin/api-server ./cmd/api-server"
    exit 1
fi

# Run the server
echo "[INFO] Starting WAF API server on :8081"
./bin/api-server
