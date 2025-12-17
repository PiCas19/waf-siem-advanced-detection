#!/bin/bash
# setup-firewall.sh - Install and configure Caddy firewall

set -e

echo "=== CADDY FIREWALL SETUP ==="

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "Error: Run as root (sudo $0)"
    exit 1
fi

# Copy scripts
echo "1. Installing scripts..."
cp caddy-firewall.sh /usr/local/bin/
cp firewall-reset.sh /usr/local/bin/
cp test-ports.sh /usr/local/bin/
cp firewall-status.sh /usr/local/bin/

chmod +x /usr/local/bin/caddy-firewall.sh
chmod +x /usr/local/bin/firewall-reset.sh
chmod +x /usr/local/bin/test-ports.sh
chmod +x /usr/local/bin/firewall-status.sh

echo "Scripts installed to /usr/local/bin/"

# Install iptables-persistent if not present
if ! command -v netfilter-persistent >/dev/null 2>&1; then
    echo "2. Installing iptables-persistent..."
    apt-get update
    apt-get install -y iptables-persistent
    echo "iptables-persistent installed"
fi

# Apply firewall rules
echo "3. Applying firewall rules..."
/usr/local/bin/caddy-firewall.sh

echo ""
echo "=== SETUP COMPLETE ==="
echo "Available commands:"
echo "  caddy-firewall.sh    - Configure firewall"
echo "  firewall-reset.sh    - Emergency reset (30s open)"
echo "  test-ports.sh        - Test port accessibility"
echo "  firewall-status.sh   - Show current status"
echo ""
echo "Firewall is now active!"