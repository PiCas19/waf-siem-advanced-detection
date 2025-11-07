# Blocking Actions Testing Guide

This guide explains how to test each blocking action in the WAF system.

## Overview of Blocking Actions

When a WAF rule is created in "Block" mode, you can choose one of these blocking actions:

1. **Block (403)** - Reject request with HTTP 403 Forbidden
2. **Drop** - Terminate connection immediately without response
3. **Redirect** - Redirect to a security page (URL configurable)
4. **Challenge** - Present CAPTCHA challenge to user
5. **None** - Only log threat (used in "Detect" mode)

## Test Environment Setup

### Prerequisites
- Running WAF instance
- API server running
- Database with custom rules
- Dashboard accessible

### Tools for Testing
- `curl` for basic HTTP requests
- `nc` (netcat) for low-level connection testing
- `ab` (Apache Bench) for load testing
- Browser for Challenge/Redirect testing
- Database query tools for verification

## Testing Each Blocking Action

### 1. Testing BLOCK Action (403 Forbidden)

#### Create a Test Rule
```bash
# Via Dashboard or API:
POST /api/rules
{
  "name": "Test Block Action",
  "pattern": "test_block_pattern_123",
  "type": "SQL Injection",
  "action": "block",
  "block_enabled": true,
  "drop_enabled": false,
  "redirect_enabled": false,
  "challenge_enabled": false
}
```

#### Test the Rule
```bash
# This should trigger the rule and return 403
curl -v "http://waf-server/api/test?search=test_block_pattern_123"

# Expected Response:
# HTTP/1.1 403 Forbidden
# X-WAF-Blocked: true
# X-WAF-Threat: Test Block Action
```

#### Verify in Audit Logs
```sql
SELECT * FROM audit_logs
WHERE action = 'BLOCK_ACTION_EXECUTED'
  AND description LIKE '%Test Block Action%'
ORDER BY created_at DESC LIMIT 1;
```

**Expected Output:**
- Status: "success"
- Description: Contains "Block" action reference
- IP Address: Your test client IP

---

### 2. Testing DROP Action (Connection Termination)

#### Create a Test Rule
```bash
POST /api/rules
{
  "name": "Test Drop Action",
  "pattern": "test_drop_pattern_456",
  "type": "Path Traversal",
  "action": "block",
  "block_enabled": false,
  "drop_enabled": true,
  "redirect_enabled": false,
  "challenge_enabled": false
}
```

#### Test the Rule with netcat
```bash
# Method 1: Using curl (shows connection error)
curl -v "http://waf-server/test?path=test_drop_pattern_456"

# Expected: Connection refused / Connection reset
# The connection closes immediately with no response

# Method 2: Using netcat (low-level)
echo "GET /test?path=test_drop_pattern_456 HTTP/1.1\r\nHost: waf-server\r\n\r\n" | nc waf-server 80

# Expected: Connection closes immediately
# You may see: (no response at all)
```

#### Verify in Audit Logs
```sql
SELECT * FROM audit_logs
WHERE action = 'DROP_ACTION_EXECUTED'
  AND description LIKE '%test_drop_pattern_456%'
ORDER BY created_at DESC LIMIT 1;
```

**Expected Output:**
- Status: "success"
- Description: Contains "Drop" action reference
- Error field: May be empty or contain "connection_dropped"

---

### 3. Testing REDIRECT Action (302 Redirect)

#### Create a Test Rule with Custom URL
```bash
POST /api/rules
{
  "name": "Test Redirect Action",
  "pattern": "test_redirect_pattern_789",
  "type": "Cross-Site Scripting",
  "action": "block",
  "block_enabled": false,
  "drop_enabled": false,
  "redirect_enabled": true,
  "challenge_enabled": false,
  "redirect_url": "https://security.example.com/blocked"
}
```

#### Test the Rule
```bash
# Follow redirects to see final destination
curl -L -v "http://waf-server/api/page?input=test_redirect_pattern_789"

# Expected Response Chain:
# HTTP/1.1 302 Found
# Location: https://security.example.com/blocked
# X-WAF-Blocked: true
# X-WAF-Threat: Test Redirect Action

# Then client follows redirect to:
# HTTP/1.1 200 OK (from security.example.com)
```

#### Browser Test
1. Open: `http://waf-server/api/page?input=test_redirect_pattern_789`
2. Expected: Browser redirects to `https://security.example.com/blocked`
3. Verify: URL in address bar changes to the redirect URL

#### Verify in Audit Logs
```sql
SELECT * FROM audit_logs
WHERE action = 'REDIRECT_ACTION_EXECUTED'
  AND description LIKE '%test_redirect_pattern_789%'
ORDER BY created_at DESC LIMIT 1;
```

**Expected Output:**
- Status: "success"
- Description: Contains "Redirect" and target URL
- Details JSON: Contains `"redirect_url": "https://security.example.com/blocked"`

---

### 4. Testing CHALLENGE Action (CAPTCHA)

#### Create a Test Rule
```bash
POST /api/rules
{
  "name": "Test Challenge Action",
  "pattern": "test_challenge_pattern_abc",
  "type": "Bot Detection",
  "action": "block",
  "block_enabled": false,
  "drop_enabled": false,
  "redirect_enabled": false,
  "challenge_enabled": true
}
```

#### Test the Rule with Browser
1. Open: `http://waf-server/api/data?query=test_challenge_pattern_abc`
2. Expected: Display CAPTCHA verification page
3. Verify elements:
   - Page title: "Security Challenge"
   - CAPTCHA widget visible
   - Submit button to verify
   - Timeout notice (if CAPTCHA service configured)

#### Test with curl (shows HTML)
```bash
curl "http://waf-server/api/data?query=test_challenge_pattern_abc"

# Expected: 403 response with HTML containing CAPTCHA
# Response headers:
# HTTP/1.1 403 Forbidden
# Content-Type: text/html; charset=utf-8
# X-WAF-Challenge: captcha-required
# X-WAF-Threat: Test Challenge Action
```

#### Verify Challenge Verification Endpoint
```bash
# After solving CAPTCHA in browser, verification happens at:
POST /api/waf/challenge/verify
{
  "token": "<captcha_token_from_service>",
  "original_request": "<challenge_id>"
}

# Expected Response:
# HTTP/1.1 200 OK
# {
#   "success": true,
#   "redirect": "/api/data?query=test_challenge_pattern_abc"
# }
```

#### Verify in Audit Logs
```sql
-- Initial challenge presented
SELECT * FROM audit_logs
WHERE action = 'CHALLENGE_ACTION_EXECUTED'
ORDER BY created_at DESC LIMIT 1;

-- After user passes challenge
SELECT * FROM audit_logs
WHERE action = 'CHALLENGE_VERIFICATION'
  AND status = 'success'
ORDER BY created_at DESC LIMIT 1;
```

**Expected Output (Challenge Presented):**
- Status: "success"
- Description: Contains "Challenge" action reference

**Expected Output (Challenge Verified):**
- Status: "success"
- Description: Contains "Challenge verified"

---

### 5. Testing NONE Action (Detect Only)

#### Create a Test Rule (Detect Mode)
```bash
POST /api/rules
{
  "name": "Test Detect Only",
  "pattern": "test_detect_pattern_xyz",
  "type": "SQL Injection",
  "action": "log",
  "block_enabled": false,
  "drop_enabled": false,
  "redirect_enabled": false,
  "challenge_enabled": false
}
```

#### Test the Rule
```bash
# Request should go through normally
curl -v "http://waf-server/api/data?search=test_detect_pattern_xyz"

# Expected: Normal response (no 403, no redirect, no challenge)
# Status: 200 OK (or whatever the app returns)
# Body: Normal application response
# Headers: No WAF-specific headers
```

#### Verify in Audit Logs
```sql
SELECT * FROM audit_logs
WHERE action = 'THREAT_DETECTED'
  AND description LIKE '%test_detect_pattern_xyz%'
ORDER BY created_at DESC LIMIT 1;
```

**Expected Output:**
- Status: "success"
- Description: "Threat detected but not blocked"
- Details JSON: `"blocked": false, "action": "log"`

---

## Batch Testing All Actions

### Test Script
```bash
#!/bin/bash

BASE_URL="http://waf-server"
THREAT_PATTERNS=(
  "test_block_pattern_123"
  "test_drop_pattern_456"
  "test_redirect_pattern_789"
  "test_challenge_pattern_abc"
  "test_detect_pattern_xyz"
)

echo "Testing all blocking actions..."
for pattern in "${THREAT_PATTERNS[@]}"; do
  echo ""
  echo "Testing pattern: $pattern"
  echo "Response:"
  curl -s -w "\nHTTP Status: %{http_code}\n\n" "$BASE_URL/api/test?input=$pattern"
done

echo ""
echo "All tests completed. Check audit logs for details:"
echo "SELECT * FROM audit_logs WHERE created_at > NOW() - INTERVAL 5 MINUTE;"
```

### Running Tests
```bash
chmod +x blocking_actions_test.sh
./blocking_actions_test.sh
```

---

## Verification Checklist

After testing each blocking action, verify:

### Block Action
- [ ] HTTP 403 returned
- [ ] Response headers include `X-WAF-Blocked: true`
- [ ] Response headers include threat name
- [ ] Audit log shows action executed
- [ ] Response time < 10ms

### Drop Action
- [ ] Connection closes immediately
- [ ] No HTTP response body
- [ ] Audit log shows action executed
- [ ] Response time < 15ms

### Redirect Action
- [ ] HTTP 302 returned
- [ ] Location header set to correct URL
- [ ] Response headers include threat name
- [ ] Browser follows redirect
- [ ] Audit log shows correct redirect URL
- [ ] Response time < 20ms

### Challenge Action
- [ ] HTTP 403 returned with HTML body
- [ ] CAPTCHA widget displayed
- [ ] Verification endpoint works
- [ ] Audit log shows challenge presented
- [ ] Audit log shows verification result
- [ ] Response time < 50ms

### Detect Only
- [ ] Request goes through normally
- [ ] Status code matches original app response
- [ ] No WAF-specific headers
- [ ] Audit log shows threat detected
- [ ] Blocked flag set to false

---

## Debugging Failed Tests

### Issue: Rule not triggering
**Solutions:**
1. Verify rule is enabled: `SELECT enabled FROM rules WHERE name = 'Test...'`
2. Check pattern syntax: Test regex in standalone tool
3. Verify rule priority: Ensure no earlier rule blocks the pattern
4. Check logs: `SELECT * FROM security_logs WHERE threat_type = '...'`

### Issue: Wrong action executed
**Solutions:**
1. Verify rule action fields: `SELECT block_enabled, drop_enabled, redirect_enabled, challenge_enabled FROM rules WHERE name = 'Test...'`
2. Check API response: Ensure rule was saved correctly
3. Verify reload: WAF may need restart to pick up changes
4. Check rule conflicts: Multiple rules may match

### Issue: No audit logs
**Solutions:**
1. Verify audit logging is enabled
2. Check database connection to audit table
3. Verify user authentication (audit logs need user context)
4. Check logs directory permissions

### Issue: Redirect not working
**Solutions:**
1. Verify redirect URL is valid (must be absolute URL)
2. Check DNS resolution of redirect domain
3. Verify redirect URL is reachable from WAF server
4. Check for circular redirects

### Issue: Challenge not displaying
**Solutions:**
1. Verify CAPTCHA service is configured
2. Check CAPTCHA API credentials
3. Verify browser JavaScript enabled
4. Check browser console for errors

---

## Performance Testing

### Load Test with Block Action
```bash
# Install: ab (Apache Bench)
# Test: 10000 requests, 100 concurrent, all trigger block rule
ab -n 10000 -c 100 "http://waf-server/api/test?input=test_block_pattern_123"

# Expected:
# - All requests blocked (HTTP 403)
# - Throughput: >1000 requests/second
# - Failed requests: 0
```

### Load Test with Redirect Action
```bash
ab -n 5000 -c 50 "http://waf-server/api/test?input=test_redirect_pattern_789"

# Expected:
# - Lower throughput than block (includes network latency)
# - All requests return 302
# - Failed requests: 0
```

---

## Production Testing Checklist

Before deploying blocking actions to production:

- [ ] All blocking actions tested in staging environment
- [ ] Performance testing completed (meets <100ms requirement)
- [ ] Fallback mechanisms tested (invalid URLs, service down, etc.)
- [ ] Audit logging verified for all actions
- [ ] Dashboard updated to show test rules
- [ ] Team trained on blocking actions behavior
- [ ] Monitoring alerts configured for blocked requests
- [ ] Customer communication prepared
- [ ] Rollback plan documented
- [ ] Production deployment scheduled in low-traffic period

---

## Additional Resources

- [WAF Rules Documentation](./docs/rules.md)
- [API Documentation](./docs/api.md)
- [Audit Logging Guide](./docs/audit-logging.md)
- [Monitoring and Alerting](./docs/monitoring.md)
