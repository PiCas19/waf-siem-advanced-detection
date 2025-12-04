# WAF Configuration Files

This directory contains all configuration files for the WAF (Web Application Firewall) system.

## 📁 Configuration Files

### 1. **rules.yaml** (Main Configuration)
The primary configuration file that controls all WAF behavior.

**Features:**
- 13 detection rule categories
- Anomaly scoring system
- Attack vector configuration
- Logging and SIEM integration
- Performance tuning
- Metrics and monitoring

**Rule Categories:**
- XSS (Cross-Site Scripting)
- SQL Injection
- NoSQL Injection
- Command Injection
- LFI (Local File Inclusion)
- RFI (Remote File Inclusion)
- Path Traversal
- XXE (XML External Entity)
- SSRF (Server-Side Request Forgery)
- LDAP Injection
- SSTI (Server-Side Template Injection)
- HTTP Response Splitting
- Prototype Pollution
- Protocol Attacks
- Session Fixation
- Scanner Detection
- Rate Limiting/DoS

### 2. **owasp-crs-rules.yaml** (OWASP Core Rule Set)
Complete OWASP ModSecurity Core Rule Set v4.0 compatible rules.

**Structure:**
```
Rule ID Ranges:
- 920xxx: Protocol Attack
- 930xxx: Local File Inclusion (LFI)
- 931xxx: Remote File Inclusion (RFI)
- 932xxx: Command Injection
- 941xxx: XSS Detection
- 942xxx: SQL Injection
- 943xxx: Session Fixation
- 912xxx: DoS/Rate Limiting
- 913xxx: Scanner Detection
- 950xxx: XXE Detection
- 951xxx: SSRF Detection
- 952xxx: NoSQL Injection
- 953xxx: LDAP Injection
- 954xxx: SSTI Detection
- 955xxx: HTTP Response Splitting
- 956xxx: Prototype Pollution
- 957xxx: Path Traversal
```

**Total Rules:** 70+

### 3. **default-rules.yaml** (Quick Start Rules)
Production-ready rules that cover the most common attacks.

**Features:**
- 30+ pre-configured rules
- Optimized for performance
- Covers OWASP Top 10 + extra threats
- Ready to use out of the box

**Rule Categories:**
- 5 XSS rules
- 5 SQL Injection rules
- 4 Command Injection rules
- 4 LFI rules
- 3 RFI/SSRF rules
- 2 XXE rules
- 1 LDAP Injection rule
- 1 NoSQL Injection rule
- 1 SSTI rule
- 1 HTTP Response Splitting rule
- 1 Scanner Detection rule
- 1 Prototype Pollution rule

### 4. **custom-rules.yaml** (User-Defined Rules)
Template for adding custom detection rules specific to your application.

**Examples Included:**
- Block specific User-Agent
- Block file extensions
- API endpoint protection
- Custom attack patterns
- Geographic restrictions
- Time-based access control
- Content-Type validation
- Header validation
- Payload size restrictions

## 🚀 Quick Start

### Basic Setup
1. Use `default-rules.yaml` for immediate protection
2. Customize `rules.yaml` for fine-tuning
3. Add application-specific rules to `custom-rules.yaml`

### Advanced Setup
1. Enable all rules in `owasp-crs-rules.yaml`
2. Configure anomaly scoring in `rules.yaml`
3. Set up SIEM integration
4. Configure metrics for monitoring

## ⚙️ Configuration Options

### Paranoia Levels (1-4)
```yaml
paranoia_level: 1  # Recommended for production
paranoia_level: 2  # More strict, some false positives
paranoia_level: 3  # Very strict, more false positives
paranoia_level: 4  # Maximum protection, many false positives
```

### Block Modes
```yaml
block_mode: true   # Block malicious requests
block_mode: false  # Log only (monitor mode)
```

### Severity Levels
- **CRITICAL**: Immediate threat (SQLi, RCE, etc.)
- **HIGH**: Serious vulnerability (XSS, LFI, etc.)
- **MEDIUM**: Potential security issue
- **LOW**: Information gathering / scanners

### Anomaly Scoring
```yaml
anomaly_scoring:
  enabled: true
  threshold:
    inbound: 5   # Block if total score >= 5
    outbound: 4  # Block response if score >= 4
```

## 🎯 Attack Vector Configuration

All detectors monitor these input vectors:
```yaml
attack_vectors:
  enabled_vectors:
    - headers           # All HTTP headers
    - cookies           # Individual cookies
    - query_params      # URL query parameters
    - post_params       # POST form data
    - json_body         # JSON payloads
    - xml_body          # XML payloads
    - url_path          # URL path
    - url_fragment      # URL fragment
    - user_agent        # User-Agent header
    - referer           # Referer header
    - origin            # Origin header
    - x_forwarded_for   # X-Forwarded-For
    - x_real_ip         # X-Real-IP
    - authorization     # Authorization header
    - content_type      # Content-Type header
    - host              # Host header
```

## 📊 Logging & SIEM Integration

### Log Format
```yaml
logging:
  format: json
  file: /var/log/caddy/waf.log
  level: info

  # SIEM integration
  siem:
    enabled: true
    format: cef  # Common Event Format
    syslog_server: "localhost:514"
```

### Log Fields
All events include:
- timestamp
- client_ip
- request_id
- method
- uri
- user_agent
- threat_type
- threat_severity
- rule_id
- attack_vector
- parameter_name
- payload
- action_taken
- anomaly_score
- matched_pattern

## 🔒 Blocklist Configuration

```yaml
blocklist:
  enabled: true
  auto_block_threshold: 5     # Block after 5 violations
  block_duration_seconds: 3600  # 1 hour
  persistent: true
  storage_path: /var/lib/caddy/waf_blocklist.db

  whitelist:
    - 127.0.0.1
    - ::1
```

## 📈 Metrics & Monitoring

### Prometheus Integration
```yaml
metrics:
  enabled: true
  endpoint: /metrics
  prometheus_format: true

  expose:
    - total_requests
    - blocked_requests
    - threats_detected_by_type
    - threats_detected_by_severity
    - response_time
    - false_positives
    - blocked_ips_count
```

## 🎛️ Performance Tuning

```yaml
performance:
  max_body_size: 10485760       # 10MB
  timeout_seconds: 30
  max_regex_execution_time: 100  # milliseconds

  # Pattern caching
  pattern_cache: true
  cache_size: 1000
  cache_ttl_seconds: 3600
```

## 🔧 Testing Your Configuration

### Test Mode
```yaml
# Set to monitor-only mode for testing
rules:
  xss:
    block_mode: false  # Will log but not block
```

### Gradual Rollout
1. Start with `block_mode: false` for all rules
2. Monitor logs for false positives
3. Enable blocking for specific rules one by one
4. Adjust anomaly thresholds as needed

## 📚 Rule Writing Guide

### Custom Rule Template
```yaml
- id: custom-xxx
  name: "Rule Name"
  description: "Detailed description"
  severity: HIGH
  category: custom-category
  patterns:
    - (?i)pattern1
    - (?i)pattern2
  enabled: true
  actions:
    - block
    - log
    - alert
```

### Pattern Syntax
- Use `(?i)` for case-insensitive matching
- Regex syntax is supported
- Special characters must be escaped: `\.`, `\(`, `\)`, etc.
- Test patterns before deploying

## 🚨 Common Issues

### False Positives
If legitimate traffic is blocked:
1. Check logs for the specific rule ID
2. Disable that rule or adjust the pattern
3. Add exceptions in `custom-rules.yaml`
4. Consider lowering paranoia level

### Performance Issues
If WAF is slow:
1. Reduce `max_body_size`
2. Disable less critical rules
3. Enable pattern caching
4. Increase `max_regex_execution_time`

## 📞 Support

For issues or questions:
- Check logs: `/var/log/caddy/waf.log`
- Review metrics: `http://your-server/metrics`
- See documentation: `../README.md`

## 🔄 Updates

Keep your rules up to date:
- Subscribe to OWASP CRS updates
- Review security advisories
- Test new rules before production deployment
