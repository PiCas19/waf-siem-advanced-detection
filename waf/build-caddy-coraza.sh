#!/bin/bash
# ==============================================================================
# Build Caddy with Dual-Layer WAF + Tailscale
# ==============================================================================

set -e

echo "[INFO] Building Caddy with Dual-Layer WAF + Tailscale..."
echo "[INFO]   Layer 1: Coraza WAF (OWASP ModSecurity Core Rule Set)"
echo "[INFO]   Layer 2: Custom WAF (Business Logic, IP Intelligence)"
echo "[INFO]   Module 3: Tailscale integration"
echo ""

# Install xcaddy if not present
if ! command -v xcaddy &> /dev/null; then
    echo "[INFO] Installing xcaddy..."
    go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
fi

# Get the absolute path to the waf module
WAF_MODULE_PATH=$(pwd)

# Build Caddy with ALL modules: Coraza, Custom WAF, Tailscale
echo "[INFO] Compiling Caddy with all modules..."
echo "[INFO]   - Coraza WAF: github.com/corazawaf/coraza-caddy/v2"
echo "[INFO]   - Custom WAF: github.com/PiCas19/waf-siem-advanced-detection/waf"
echo "[INFO]   - Tailscale: github.com/tailscale/caddy-tailscale"
echo ""

xcaddy build v2.10.2 \
    --with github.com/corazawaf/coraza-caddy/v2@latest \
    --with github.com/PiCas19/waf-siem-advanced-detection/waf=$WAF_MODULE_PATH \
    --with github.com/tailscale/caddy-tailscale

echo ""
echo "[SUCCESS] Build completed successfully!"
echo "[INFO] Binary location: ./caddy"
echo ""
echo "[INFO] Verify modules are loaded:"
echo "  ./caddy list-modules | grep -E '(coraza|waf|tailscale)'"
echo ""
echo "[INFO] Next steps:"
echo "  1. sudo systemctl stop caddy"
echo "  2. sudo cp ./caddy /usr/bin/caddy"
echo "  3. sudo chmod +x /usr/bin/caddy"
echo "  4. sudo setcap CAP_NET_BIND_SERVICE=+eip /usr/bin/caddy"
echo "  5. sudo systemctl start caddy"
