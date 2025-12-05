#!/bin/bash
# ==============================================================================
# Deploy Dual-Layer WAF (Coraza + Custom WAF) on Server
# ==============================================================================

set -e

echo "[INFO] Deploying Dual-Layer WAF..."
echo "[INFO]   Layer 1: Coraza WAF (OWASP ModSecurity Core Rule Set)"
echo "[INFO]   Layer 2: Custom WAF (Business Logic, IP Intelligence)"
echo ""

# Get absolute path to project directory (before any cd commands)
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WAF_DIR="$PROJECT_DIR"

# Verify required files exist
echo "[INFO] Verifying required files..."
if [ ! -f "$WAF_DIR/coraza.conf" ]; then
    echo "[ERROR] coraza.conf not found in $WAF_DIR"
    exit 1
fi
if [ ! -f "$WAF_DIR/Caddyfile" ]; then
    echo "[ERROR] Caddyfile not found in $WAF_DIR"
    exit 1
fi
if [ ! -f "$WAF_DIR/build-caddy-coraza.sh" ]; then
    echo "[ERROR] build-caddy-coraza.sh not found in $WAF_DIR"
    exit 1
fi

echo "[INFO] All required files found in $WAF_DIR"
echo ""

# 1. Create directories
echo "[STEP 1/12] Creating directories..."
sudo mkdir -p /etc/caddy/waf
sudo mkdir -p /var/log/caddy

# 2. Download OWASP Core Rule Set
echo "[STEP 2/12] Downloading OWASP Core Rule Set v4.0..."

# Create temporary directory in home (avoid /tmp space issues)
TMPDIR=$(mktemp -d -p "$HOME")
echo "[INFO] Using temporary directory: $TMPDIR"
cd "$TMPDIR"

# Download with progress and retries
wget --show-progress --tries=3 --timeout=30 \
    -O coreruleset.tar.gz \
    https://github.com/corazawaf/coraza-coreruleset/archive/refs/tags/v4.0.0.tar.gz

# Verify download succeeded
if [ ! -f coreruleset.tar.gz ]; then
    echo "[ERROR] Download failed"
    cd - > /dev/null
    rm -rf "$TMPDIR"
    exit 1
fi

# Verify file is not empty
if [ ! -s coreruleset.tar.gz ]; then
    echo "[ERROR] Downloaded file is empty"
    cd - > /dev/null
    rm -rf "$TMPDIR"
    exit 1
fi

# Extract
echo "[STEP 2/12] Extracting OWASP Core Rule Set..."
tar -xzf coreruleset.tar.gz

# Verify extraction succeeded
if [ ! -d coraza-coreruleset-4.0.0 ]; then
    echo "[ERROR] Extraction failed"
    cd - > /dev/null
    rm -rf "$TMPDIR"
    exit 1
fi

# Move to final location
sudo mv coraza-coreruleset-4.0.0 /etc/caddy/waf/coreruleset

# Cleanup
cd - > /dev/null
rm -rf "$TMPDIR"

# 3. Copy Coraza configuration
echo "[STEP 3/12] Copying Coraza configuration..."
sudo cp "$WAF_DIR/coraza.conf" /etc/caddy/waf/coraza.conf

# 4. Copy updated Caddyfile
echo "[STEP 4/12] Copying updated Caddyfile..."
sudo cp "$WAF_DIR/Caddyfile" /etc/caddy/Caddyfile

# 5. Set proper permissions
echo "[STEP 5/12] Setting permissions..."
sudo chown -R caddy:caddy /etc/caddy/waf
sudo chown -R caddy:caddy /var/log/caddy
sudo chmod 644 /etc/caddy/waf/coraza.conf
sudo chmod 644 /etc/caddy/Caddyfile

# 6. Build Caddy with all modules
echo "[STEP 6/12] Building Caddy with Coraza + Custom WAF + Tailscale..."
cd "$WAF_DIR"
chmod +x build-caddy-coraza.sh
./build-caddy-coraza.sh

# 7. Stop Caddy service
echo "[STEP 7/12] Stopping Caddy..."
sudo systemctl stop caddy

# 8. Replace Caddy binary
echo "[STEP 8/12] Replacing Caddy binary..."
sudo cp ./caddy /usr/bin/caddy
sudo chmod +x /usr/bin/caddy
sudo setcap CAP_NET_BIND_SERVICE=+eip /usr/bin/caddy

# 9. Validate Caddyfile
echo "[STEP 9/12] Validating Caddyfile..."
sudo caddy validate --config /etc/caddy/Caddyfile

# 10. Start Caddy service
echo "[STEP 10/12] Starting Caddy with Dual-Layer WAF..."
sudo systemctl start caddy

# 11. Verify all modules are loaded
echo "[STEP 11/12] Verifying WAF modules..."
caddy list-modules | grep -E '(coraza|waf|tailscale)' || true

# 12. Check status
echo "[STEP 12/12] Checking Caddy status..."
sudo systemctl status caddy --no-pager

echo ""
echo "[SUCCESS] Dual-Layer WAF deployment completed!"
echo ""
echo "[INFO] Architecture:"
echo "   Request -> Coraza WAF (Layer 1) -> Custom WAF (Layer 2) -> Backend"
echo ""
echo "[INFO] Monitoring:"
echo "   Coraza logs:     tail -f /var/log/caddy/coraza_audit.log"
echo "   Custom WAF logs: tail -f /var/log/caddy/waf_wan.log"
echo "   Caddy access:    tail -f /var/log/caddy/access_wan.log"
echo ""
echo "[TEST] WAF blocking (XSS):"
echo "   curl -k 'https://172.16.216.10:9443/finance?test=<script>alert(1)</script>'"
echo "   Expected: 403 Forbidden (blocked by Coraza Layer 1)"
echo ""
echo "[TEST] WAF blocking (SQLi):"
echo "   curl -k 'https://172.16.216.10:9443/industrial?id=1%20OR%201=1'"
echo "   Expected: 403 Forbidden (blocked by Coraza Layer 1)"
echo ""
echo "[INFO] Custom WAF features (Layer 2):"
echo "   - Blocklist IP: Add IP via dashboard -> blocked by Layer 2"
echo "   - Whitelist IP: Add IP via dashboard -> bypass both layers"
echo "   - Custom Rules: Create via dashboard -> enforced by Layer 2"
