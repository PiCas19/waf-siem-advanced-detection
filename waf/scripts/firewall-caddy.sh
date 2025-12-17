#!/bin/bash
# caddy-firewall.sh - Firewall for Caddy server
# Blocks everything except Caddy ports

set -e

# Configuration
CADDY_WAN_PORT="9443"
CADDY_LAN_PORTS="80 443 8080 8443"
BACKEND_PORTS="3000 3001"
API_PORTS="8081 8082 8083"
SSH_PORT="22"

DMZ_NET="172.16.216.0/24"
LAN_NET="192.168.216.0/24"

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "Error: Run as root (sudo $0)"
    exit 1
fi

echo "Starting Caddy firewall configuration..."

# Backup current rules
mkdir -p /var/backup/iptables
iptables-save > "/var/backup/iptables/backup_$(date +%Y%m%d_%H%M%S).rules"
echo "Backup created"

# Reset all rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

echo "Default policies set: INPUT DROP, FORWARD DROP, OUTPUT ACCEPT"

# Basic rules
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# ICMP (ping)
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

echo "Basic rules configured"

# Caddy WAN port (9443) - from anywhere
iptables -A INPUT -p tcp --dport $CADDY_WAN_PORT -j ACCEPT
echo "Port $CADDY_WAN_PORT (Caddy WAN) open to all"

# Caddy LAN ports - only from internal networks
for port in $CADDY_LAN_PORTS; do
    iptables -A INPUT -s $DMZ_NET -p tcp --dport $port -j ACCEPT
    iptables -A INPUT -s $LAN_NET -p tcp --dport $port -j ACCEPT
    echo "Port $port (Caddy LAN) open to $DMZ_NET, $LAN_NET"
done

# Backend ports (3000, 3001) - only from localhost and DMZ
for port in $BACKEND_PORTS; do
    iptables -A INPUT -s 127.0.0.1/32 -p tcp --dport $port -j ACCEPT
    iptables -A INPUT -s $DMZ_NET -p tcp --dport $port -j ACCEPT
    echo "Port $port (backend) open to localhost, $DMZ_NET"
done

# API ports (8081-8083) - only from localhost
for port in $API_PORTS; do
    iptables -A INPUT -s 127.0.0.1/32 -p tcp --dport $port -j ACCEPT
    echo "Port $port (API) open to localhost only"
done

# SSH - only from trusted networks
iptables -A INPUT -s $DMZ_NET -p tcp --dport $SSH_PORT -j ACCEPT
iptables -A INPUT -s $LAN_NET -p tcp --dport $SSH_PORT -j ACCEPT
echo "SSH (port $SSH_PORT) open to $DMZ_NET, $LAN_NET"

# Security: SSH rate limiting
iptables -A INPUT -p tcp --dport $SSH_PORT -m state --state NEW -m recent --set
iptables -A INPUT -p tcp --dport $SSH_PORT -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
echo "SSH brute force protection enabled"

# Save rules
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4
echo "Rules saved to /etc/iptables/rules.v4"

# Make persistent
if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save
    echo "Rules made persistent"
else
    echo "Install iptables-persistent for permanent rules:"
    echo "  apt-get install iptables-persistent"
fi

echo ""
echo "=== FIREWALL STATUS ==="
echo "Open ports:"
echo "  WAN (all):           $CADDY_WAN_PORT"
echo "  LAN (internal):      $CADDY_LAN_PORTS"
echo "  Backend (local/DMZ): $BACKEND_PORTS"
echo "  API (localhost):     $API_PORTS"
echo "  SSH (trusted nets):  $SSH_PORT"
echo ""
echo "Allowed networks:"
echo "  DMZ: $DMZ_NET"
echo "  LAN: $LAN_NET"
echo ""
echo "Caddy firewall configuration complete!"