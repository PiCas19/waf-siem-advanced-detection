# WAF Dual-Layer Architecture

## Overview

Sistema di protezione a due livelli che combina OWASP standard rules con logica business custom.

```
Request
   |
   v
┌─────────────────────────────────────────────────┐
│ LAYER 1: Coraza WAF (OWASP ModSecurity CRS)    │
│ - 200+ regole OWASP automatiche                 │
│ - Evasion techniques detection                  │
│ - Scanner detection                             │
│ - Protocol validation                           │
└─────────────────┬───────────────────────────────┘
                  | PASS
                  v
┌─────────────────────────────────────────────────┐
│ LAYER 2: Custom WAF (Business Logic)           │
│                                                 │
│ ┌─────────────────────────────────────────┐   │
│ │ 1. Whitelist Check                      │   │
│ │    - Bypass all if IP whitelisted       │   │
│ └─────────────────────────────────────────┘   │
│                  |                             │
│                  v                             │
│ ┌─────────────────────────────────────────┐   │
│ │ 2. Blocklist Check                      │   │
│ │    - Block if IP blocklisted            │   │
│ └─────────────────────────────────────────┘   │
│                  |                             │
│                  v                             │
│ ┌─────────────────────────────────────────┐   │
│ │ 3. Threat Detection (3 rule types)      │   │
│ │    a) Default Rules (builtin)           │   │
│ │    b) Custom Rules (database)           │   │
│ │    c) Manual Block Rules (priority)     │   │
│ └─────────────────────────────────────────┘   │
└─────────────────┬───────────────────────────────┘
                  | PASS
                  v
            Backend Application
```

---

## Layer 1: Coraza WAF (OWASP Protection)

### Configuration
- File: `/etc/caddy/waf/coraza.conf`
- Rule Set: OWASP ModSecurity Core Rule Set v4.0
- Rules Location: `/etc/caddy/waf/coreruleset/`

### Protection Coverage

#### Standard OWASP Rules (200+ rules)
- XSS (Cross-Site Scripting) - 50+ patterns
- SQL Injection - 80+ patterns
- RCE (Remote Code Execution)
- Path Traversal
- Command Injection
- Scanner Detection (Nikto, SQLMap, Nmap)
- Protocol Attacks (HTTP violations)
- Data Leakage Prevention

#### Advanced Features
- Evasion technique detection (unicode, double encoding, mutations)
- Anomaly scoring system
- Protocol validation
- Response inspection

#### Custom Rules (Application-Specific)
```
ID Range 9000-9999: Custom protection rules

9001-9003:   XSS Protection
9010-9012:   SQL Injection Protection
9020-9021:   Path Traversal Protection
9030-9031:   Command Injection Protection
9040:        RFI Protection
9050:        SSTI Protection
9060:        LDAP Protection
9070:        XXE Protection
9080:        NoSQL Protection
9100-9110:   Dashboard Protection
9200-9201:   Finance Application Protection
9300-9301:   Industrial Application Protection
9400:        Rate Limiting Markers
9500-9502:   Common Attack Patterns
9600-9601:   Information Disclosure Prevention
```

### Logging
```bash
# Audit log (blocked requests)
/var/log/caddy/coraza_audit.log

# Debug log (detailed inspection)
/var/log/caddy/coraza_debug.log
```

---

## Layer 2: Custom WAF (Business Logic)

### Configuration
- Code: `waf/pkg/waf/middleware.go`
- Detectors: `waf/internal/detector/*.go`
- API Endpoints: `http://localhost:8081/api/waf/*`

### Priority Order

```
Priority 1: Whitelist Check
   └─> IP whitelisted? → BYPASS all layers (allow request)

Priority 2: Blocklist Check
   └─> IP blocklisted? → BLOCK (403)

Priority 3: Threat Detection
   ├─> Manual Block Rules (highest priority)
   ├─> Default Rules (builtin detectors)
   └─> Custom Rules (database-managed)
```

---

## Rule Types in Layer 2

### Type 1: Default Rules (Builtin Detectors)

**Location:** `waf/internal/detector/*.go`

**Characteristics:**
- Hardcoded in Go code
- ~100 detection patterns
- Always active (cannot disable via dashboard)
- Controlled by `block_mode` setting in Caddyfile

**Detectors:**
```go
XSSDetector              // ~20 patterns
SQLiDetector             // ~30 patterns
CommandInjectionDetector // Command injection patterns
LFIDetector              // Local file inclusion
RFIDetector              // Remote file inclusion
SSRFDetector             // Server-side request forgery
SSTIDetector             // Template injection
XXEDetector              // XML external entity
NoSQLInjectionDetector   // MongoDB injection
LDAPInjectionDetector    // LDAP injection
PathTraversalDetector    // Directory traversal
PrototypePollutionDetector // JS prototype pollution
ResponseSplittingDetector  // HTTP response splitting
```

**Example - XSS Default Rules:**
```go
// waf/internal/detector/xss.go
patterns := []string{
    `(?i)<script[^>]*>`,
    `(?i)javascript\s*:`,
    `(?i)on(load|error|click|mouseover)\s*=`,
    `(?i)<iframe[^>]*(src|onload)\s*=`,
    `(?i)eval\s*\(`,
    // ... more patterns
}
```

**Behavior:**
- If `block_mode: true` in Caddyfile → BLOCK detected threats
- If `block_mode: false` in Caddyfile → LOG only (detect mode)

**Logging:**
```json
{
  "threat_type": "XSS",
  "severity": "CRITICAL",
  "description": "XSS pattern detected",
  "blocked": true,
  "blocked_by": "auto"
}
```

---

### Type 2: Custom Rules (Database-Managed)

**Location:** Database (via API)

**Characteristics:**
- Created via Dashboard UI
- Stored in database
- Dynamically loaded every 10 seconds
- Regex-based pattern matching
- Configurable action: `log` or `block`

**API Endpoint:**
```
GET /api/waf/custom-rules
```

**Rule Structure:**
```go
type CustomRule struct {
    ID               uint
    Name             string
    Pattern          string   // Regex pattern
    Type             string   // Rule category
    Severity         string   // CRITICAL, HIGH, MEDIUM, LOW
    Enabled          bool
    Action           string   // "log" or "block"
    BlockEnabled     bool
    DropEnabled      bool
    RedirectEnabled  bool
    ChallengeEnabled bool
    RedirectURL      string
    IsManualBlock    bool    // Manual block has priority
}
```

**Example - Custom Rule via Dashboard:**
```
Name: Block API Scanner
Pattern: .*\/api\/admin.*
Type: scanner
Severity: HIGH
Action: block
```

**Actions:**
- `action="log"` → Detect and log only (not block)
- `action="block"` → Block request with specified action:
  - `block` → Return 403 Forbidden
  - `drop` → Close connection immediately
  - `redirect` → Redirect to URL
  - `challenge` → Show Cloudflare Turnstile CAPTCHA

**Logging:**
```json
{
  "threat_type": "scanner",
  "severity": "HIGH",
  "description": "Block API Scanner",
  "blocked": true,
  "blocked_by": "auto"
}
```

---

### Type 3: Manual Block Rules

**Location:** Database (via Dashboard "Block" action)

**Characteristics:**
- Created when admin clicks "Block" on a detected threat
- Highest priority among custom rules
- Always blocks (ignores `block_mode` setting)
- `IsManualBlock = true` flag

**Creation Flow:**
```
1. Threat detected by Default Rule or Custom Rule
2. Admin sees threat in Dashboard
3. Admin clicks "Block this threat"
4. System creates Custom Rule with IsManualBlock=true
5. Future requests matching this rule are blocked immediately
```

**Priority:**
```
Manual Block Rules > Custom Rules (action=block) > Default Rules
```

**Example:**
```
Admin sees: XSS attack from IP 192.168.1.100
Admin action: Click "Block"
System creates:
  - Custom Rule: Pattern matching the payload
  - IsManualBlock: true
  - Always blocks, regardless of block_mode
```

**Logging:**
```json
{
  "threat_type": "XSS",
  "severity": "CRITICAL",
  "description": "Manual block rule",
  "blocked": true,
  "blocked_by": "manual"
}
```

---

## Request Flow Example

### Example 1: XSS Attack (Standard)

```
Request: GET /finance?q=<script>alert(1)</script>

Layer 1 (Coraza):
  - Rule 941100 matches: XSS pattern
  - Action: BLOCK
  - Response: 403 Forbidden
  - Log: /var/log/caddy/coraza_audit.log

Layer 2 (Custom WAF):
  - Never reached

Result: Request blocked by Layer 1
```

### Example 2: Blocklisted IP

```
Request: GET /finance (from IP 192.168.1.100 in blocklist)

Layer 1 (Coraza):
  - No malicious payload
  - Action: PASS

Layer 2 (Custom WAF):
  - Whitelist check: Not whitelisted
  - Blocklist check: IP found in blocklist
  - Action: BLOCK
  - Response: 403 Forbidden
  - Log: /var/log/caddy/waf.log + Dashboard

Result: Request blocked by Layer 2 (blocklist)
```

### Example 3: Whitelisted Admin IP

```
Request: GET /finance?q=<script>alert(1)</script> (from IP 100.115.217.37 whitelisted)

Layer 1 (Coraza):
  - Rule 941100 matches: XSS pattern
  - Action: Inspected but...

Layer 2 (Custom WAF):
  - Whitelist check: IP 100.115.217.37 found
  - Action: BYPASS all checks
  - Response: 200 OK (request passes to backend)
  - Log: Whitelisted IP bypass

Result: Request allowed (useful for admin testing)
```

### Example 4: Custom Business Rule

```
Request: GET /api/admin/users (from untrusted network)

Layer 1 (Coraza):
  - Valid HTTP request
  - No OWASP violations
  - Action: PASS

Layer 2 (Custom WAF):
  - Whitelist check: Not whitelisted
  - Blocklist check: Not blocklisted
  - Default Rules: No match
  - Custom Rules: Matches "Block Admin API Access"
  - Action: BLOCK (action=block)
  - Response: 403 Forbidden
  - Log: /var/log/caddy/waf.log + Dashboard

Result: Request blocked by Layer 2 (custom rule)
```

### Example 5: Manual Block Priority

```
Request: GET /finance?payload=malicious_string

Layer 1 (Coraza):
  - No standard OWASP match
  - Action: PASS

Layer 2 (Custom WAF):
  - Whitelist check: Not whitelisted
  - Blocklist check: Not blocklisted
  - Manual Block Rules: Matches (admin blocked this pattern before)
  - Action: BLOCK (highest priority)
  - Response: 403 Forbidden
  - Log: blocked_by="manual"

Result: Request blocked by Layer 2 (manual block rule)
```

---

## Configuration Files

### Caddyfile (Dual-Layer Setup)

```caddy
{
    order coraza_waf first
    order waf before reverse_proxy
}

:443 {
    # Layer 1: Coraza WAF
    coraza_waf {
        directives `
            Include /etc/caddy/waf/coraza.conf
        `
    }

    # Layer 2: Custom WAF
    waf {
        log_file /var/log/caddy/waf.log
        block_mode true
        api_endpoint http://localhost:8081/api
        rules_endpoint http://localhost:8081/api/waf/custom-rules
        blocklist_endpoint http://localhost:8081/api/waf/blocklist
        whitelist_endpoint http://localhost:8081/api/waf/whitelist

        enable_tailscale_detection true
        enable_dmz_detection true
        trusted_proxies 127.0.0.1 ::1
    }

    reverse_proxy backend:3000
}
```

### Layer 2 Block Mode

**block_mode: true** (Production)
- Default Rules: BLOCK detected threats
- Custom Rules with action="block": BLOCK
- Custom Rules with action="log": LOG only
- Manual Block Rules: BLOCK always

**block_mode: false** (Monitoring)
- Default Rules: LOG only (detect mode)
- Custom Rules with action="block": Still BLOCK
- Custom Rules with action="log": LOG only
- Manual Block Rules: BLOCK always

---

## Dashboard Management

### Whitelist IP
```
Dashboard → WAF → Whitelist → Add IP
Effect: Bypass both Layer 1 and Layer 2
Use case: Admin IPs, trusted services
```

### Blocklist IP
```
Dashboard → WAF → Blocklist → Add IP
Effect: Block at Layer 2 (after Coraza)
Use case: Known attackers, banned IPs
```

### Custom Rule (action=log)
```
Dashboard → WAF → Rules → Create
Action: log
Effect: Detect and log only (not block)
Use case: Testing new rules, monitoring
```

### Custom Rule (action=block)
```
Dashboard → WAF → Rules → Create
Action: block
Effect: Block matching requests
Use case: Business-specific protection
```

### Manual Block
```
Dashboard → Logs → View Threat → Block
Effect: Create Manual Block Rule (highest priority)
Use case: Block specific attack pattern immediately
```

---

## Monitoring

### Logs Locations

```bash
# Layer 1 (Coraza OWASP)
/var/log/caddy/coraza_audit.log   # Blocked requests
/var/log/caddy/coraza_debug.log   # Debug info

# Layer 2 (Custom WAF)
/var/log/caddy/waf_wan.log         # WAN traffic
/var/log/caddy/waf_lan.log         # LAN traffic

# General
/var/log/caddy/access_wan.log      # All access logs
```

### Real-Time Monitoring

```bash
# Watch both layers
watch -n 1 'tail -20 /var/log/caddy/coraza_audit.log && echo "---" && tail -20 /var/log/caddy/waf_wan.log'

# Count blocks per layer
echo "Layer 1 (Coraza):" && grep -c "403" /var/log/caddy/coraza_audit.log
echo "Layer 2 (Custom):" && grep -c '"blocked":true' /var/log/caddy/waf_wan.log
```

### Dashboard Statistics

```
http://your-server:8080

- Total threats detected (both layers)
- Threats by type
- Blocked IPs
- Custom rules effectiveness
- Real-time threat map
```

---

## Performance Considerations

### Rule Processing Order (Layer 2)

```
1. Whitelist Check - O(1) hash lookup
2. Blocklist Check - O(1) hash lookup
3. Manual Block Rules - O(n) regex match, n = manual rules
4. Default Rules - O(m) regex match, m = builtin patterns
5. Custom Rules - O(k) regex match, k = custom rules
```

### Caching

**Layer 2 Caching:**
- Custom rules: Reloaded every 10 seconds
- Blocklist: Reloaded every 10 seconds
- Whitelist: Reloaded every 10 seconds
- Request fingerprints: 3-second deduplication window

**Performance Impact:**
- Coraza (C native): ~0.1ms per request
- Custom WAF (Go): ~0.5ms per request
- Total overhead: ~0.6ms per request

---

## Best Practices

### 1. Use Whitelist for Trusted IPs
```
Whitelist your admin IPs to bypass all checks
Useful for testing and maintenance
```

### 2. Start with Monitoring Mode
```
Set block_mode: false initially
Monitor logs for false positives
Enable blocking gradually
```

### 3. Custom Rules Workflow
```
1. Create rule with action="log"
2. Monitor logs for 24-48 hours
3. If no false positives, change to action="block"
4. Keep monitoring
```

### 4. Layer Responsibilities
```
Layer 1 (Coraza): OWASP standard attacks
Layer 2 (Custom): Business logic, IP management
Don't duplicate rules between layers
```

### 5. Manual Block Usage
```
Use Manual Block for:
- Immediate threat response
- Specific attack patterns
- Zero-day attacks

Avoid Manual Block for:
- Standard attacks (use Coraza)
- Temporary issues (use Blocklist)
```

---

## Troubleshooting

### False Positive (Legitimate Traffic Blocked)

**Layer 1 (Coraza):**
```bash
# Check which rule triggered
tail /var/log/caddy/coraza_audit.log | grep "403"

# Adjust Coraza paranoia level in coraza.conf
SecRuleEngine On  # Change to DetectionOnly for testing

# Or whitelist the IP
Dashboard → Whitelist → Add IP
```

**Layer 2 (Custom WAF):**
```bash
# Check which rule triggered
tail /var/log/caddy/waf.log | jq '.threat_type, .description'

# Disable the rule
Dashboard → Rules → Find rule → Disable

# Or whitelist the IP
Dashboard → Whitelist → Add IP
```

### Performance Issues

```bash
# Check rule count
curl http://localhost:8081/api/waf/custom-rules | jq '. | length'

# Review complex regex patterns
Dashboard → Rules → Review patterns

# Disable unused rules
Dashboard → Rules → Disable
```

### Not Blocking Attacks

```bash
# Verify both modules loaded
caddy list-modules | grep -E '(coraza|waf)'

# Check Coraza config
ls -la /etc/caddy/waf/coraza.conf

# Check Custom WAF block_mode
grep "block_mode" /etc/caddy/Caddyfile

# Check logs
tail -f /var/log/caddy/coraza_audit.log
tail -f /var/log/caddy/waf.log
```

---

## Summary

### Layer 1: Coraza WAF
- 200+ OWASP rules automatic
- Evasion techniques detection
- Scanner detection
- Protocol validation

### Layer 2: Custom WAF (3 Rule Types)
1. **Default Rules:** ~100 builtin patterns (XSS, SQLi, etc.)
2. **Custom Rules:** Database-managed, regex-based
3. **Manual Block Rules:** Highest priority, admin-created

### Defense in Depth
- Two independent security layers
- If one bypasses, the other covers
- Flexible management via Dashboard
- Complete visibility with dual logging
