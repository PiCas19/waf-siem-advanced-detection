#!/bin/bash
# firewall-status.sh - Show current firewall status

echo "=== FIREWALL STATUS ==="
echo ""
echo "Current iptables rules:"
echo "-----------------------"
iptables -L -n --line-numbers
echo ""
echo "Listening ports:"
echo "----------------"
ss -tulpn | grep LISTEN
echo ""
echo "Connection count per port:"
echo "--------------------------"
netstat -tun | awk '{print $4}' | grep ':' | cut -d: -f2 | sort -n | uniq -c | sort -rn