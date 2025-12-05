#!/bin/bash
# ==============================================================================
# Build Caddy with Coraza WAF + Custom WAF + Tailscale
# ==============================================================================

set -e

echo "[INFO] Building Caddy with all modules..."
echo "[INFO]   - Caddy v2.10.2"
echo "[INFO]   - Coraza WAF (OWASP ModSecurity Core Rule Set)"
echo "[INFO]   - Custom WAF (Business Logic + IP Intelligence)"
echo "[INFO]   - Tailscale VPN"
echo ""

# Get absolute path to WAF module
WAF_MODULE_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[INFO] WAF module path: $WAF_MODULE_PATH"
echo ""

# Check if xcaddy is installed
if ! command -v xcaddy &> /dev/null; then
    echo "[ERROR] xcaddy is not installed"
    echo "[INFO] Install with: go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest"
    exit 1
fi

echo "[INFO] xcaddy version:"
xcaddy version
echo ""

# Build Caddy with all modules
echo "[INFO] Building Caddy..."
xcaddy build v2.10.2 \
    --with github.com/corazawaf/coraza-caddy/v2@latest \
    --with github.com/PiCas19/waf-siem-advanced-detection/waf="$WAF_MODULE_PATH" \
    --with github.com/tailscale/caddy-tailscale

# Verify build succeeded
if [ ! -f "./caddy" ]; then
    echo "[ERROR] Build failed - caddy binary not found"
    exit 1
fi

echo ""
echo "[SUCCESS] Caddy built successfully!"
echo ""

# Show binary info
echo "[INFO] Binary info:"
ls -lh ./caddy
echo ""

# List loaded modules
echo "[INFO] Verifying modules..."
./caddy list-modules | grep -E '(coraza|waf|tailscale)' || true
echo ""

echo "[SUCCESS] Build complete!"
echo "[INFO] Binary location: ./caddy"
echo "[INFO] To install: sudo cp ./caddy /usr/bin/caddy"
