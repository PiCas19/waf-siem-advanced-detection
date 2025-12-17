#!/bin/bash
# firewall-reset.sh - Emergency firewall reset
# Opens everything for 30 seconds, then restores

echo "WARNING: Emergency firewall reset!"
echo "All ports will be open for 30 seconds!"

# Backup current rules
iptables-save > /tmp/iptables_emergency_backup.rules
echo "Current rules backed up to /tmp/iptables_emergency_backup.rules"

# Reset to ACCEPT everything
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

echo "Firewall DISABLED - ALL PORTS OPEN"
echo "You have 30 seconds to fix configuration issues..."
echo "After that, original rules will be restored."

# Wait 30 seconds
sleep 30

# Restore original rules
echo "Restoring original firewall rules..."
iptables-restore < /tmp/iptables_emergency_backup.rules

echo "Firewall rules restored!"
echo "Run 'iptables -L -n' to verify."