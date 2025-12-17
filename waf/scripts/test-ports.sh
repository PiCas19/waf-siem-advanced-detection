#!/bin/bash
# test-ports.sh - Test if Caddy ports are accessible

PORTS_TO_TEST="9443 80 443 8080 8443 3000 3001 22"
TEST_IP="172.16.216.10"

echo "Testing port accessibility on $TEST_IP..."
echo ""

for port in $PORTS_TO_TEST; do
    # Try TCP connection
    if timeout 2 bash -c "echo > /dev/tcp/$TEST_IP/$port" 2>/dev/null; then
        echo "Port $port: OPEN"
    else
        echo "Port $port: CLOSED or not responding"
    fi
done

echo ""
echo "Testing from localhost:"
nc -z -v -w2 localhost 9443 2>&1 | grep -q "succeeded" && \
    echo "Port 9443 reachable from localhost" || \
    echo "Port 9443 not reachable from localhost"

echo ""
echo "Current listening ports:"
ss -tulpn | grep -E '(9443|80|443|8080|8443|3000|3001|22)'