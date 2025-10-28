#!/bin/bash

# Script to run the WAF API server with MaxMind GeoIP support

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

# Create bin directory if it doesn't exist
mkdir -p ./bin

# Check if binary exists, if not build it
if [ ! -f "./bin/api-server" ]; then
    echo "[INFO] Binary not found, building the server..."
    go build -o bin/api-server ./cmd/api-server
    if [ $? -ne 0 ]; then
        echo "[ERROR] Build failed"
        exit 1
    fi
    echo "[INFO] Build completed successfully"
else
    echo "[INFO] Using existing binary"
fi

# Run the server
echo "[INFO] Starting WAF API server on :8081"
./bin/api-server
