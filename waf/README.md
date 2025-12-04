# Dual-Layer WAF for Caddy

Enterprise-grade Web Application Firewall with dual-layer protection: OWASP ModSecurity Core Rule Set (Layer 1) + Custom Business Logic WAF (Layer 2).

## Architecture

```
Request → Coraza WAF (Layer 1) → Custom WAF (Layer 2) → Backend
         [OWASP CRS]              [Business Logic]
```

### Layer 1: Coraza WAF
- OWASP ModSecurity Core Rule Set v4.0
- 200+ automatic protection rules
- XSS, SQLi, RCE, Path Traversal, Scanner Detection
- Configuration: `coraza.conf`

### Layer 2: Custom WAF
- Dynamic rules from database (API-managed)
- Blocklist/Whitelist IP management
- IP Intelligence (Tailscale, DMZ, HMAC validation)
- Advanced detectors (SSRF, SSTI, XXE, NoSQL, LDAP)
- Blocking actions (block, drop, redirect, challenge)
- Dashboard integration

## Features

### Layer 1 Protection (Coraza)
- XSS (Cross-Site Scripting)
- SQL Injection
- Remote Code Execution (RCE)
- Path Traversal
- Command Injection
- Scanner Detection
- Protocol Attacks
- Data Leakage Prevention
- OWASP Top 10 coverage

### Layer 2 Protection (Custom WAF)
- Custom Rules (database-managed)
- IP Blocklist/Whitelist
- IP Intelligence
  - Tailscale network detection
  - DMZ network detection
  - HMAC signature validation
- Advanced Attack Detection
  - SSRF (Server-Side Request Forgery)
  - SSTI (Server-Side Template Injection)
  - XXE (XML External Entity)
  - NoSQL Injection
  - LDAP Injection
  - Prototype Pollution
- Flexible Blocking Actions
  - Block (403 Forbidden)
  - Drop (close connection)
  - Redirect (302 redirect)
  - Challenge (Cloudflare Turnstile CAPTCHA)
- Dashboard Integration
  - Real-time threat monitoring
  - Custom rule management
  - IP management
  - Statistics and analytics

## Installation

### Quick Deploy (Recommended)

```bash
# 1. Copy files to server
scp build-caddy-coraza.sh deploy-coraza.sh coraza.conf Caddyfile caddy@server:~/waf-siem-advanced-detection/waf/

# 2. SSH to server
ssh caddy@server
cd ~/waf-siem-advanced-detection/waf

# 3. Run deployment script
chmod +x deploy-coraza.sh
./deploy-coraza.sh
```

### Manual Build

```bash
# Build Caddy with all modules
chmod +x build-caddy-coraza.sh
./build-caddy-coraza.sh

# Verify modules loaded
./caddy list-modules | grep -E '(coraza|waf|tailscale)'
```

### Build Command

```bash
xcaddy build v2.10.2 \
    --with github.com/corazawaf/coraza-caddy/v2@latest \
    --with github.com/PiCas19/waf-siem-advanced-detection/waf=./ \
    --with github.com/tailscale/caddy-tailscale
```

## Configuration

### Caddyfile Example

```caddy
{
    order coraza_waf first
    order waf before reverse_proxy
}

:443 {
    # Layer 1: Coraza WAF (OWASP)
    coraza_waf {
        directives `
            Include /etc/caddy/waf/coraza.conf
        `
    }

    # Layer 2: Custom WAF (Business Logic)
    waf {
        log_file /var/log/caddy/waf.log
        block_mode true
        api_endpoint http://localhost:8081/api
        rules_endpoint http://localhost:8081/api/waf/custom-rules
        blocklist_endpoint http://localhost:8081/api/waf/blocklist
        whitelist_endpoint http://localhost:8081/api/waf/whitelist

        # IP Intelligence
        enable_tailscale_detection true
        tailscale_networks 100.64.0.0/10
        enable_dmz_detection true
        dmz_networks 172.16.216.0/24

        trusted_proxies 127.0.0.1 ::1
    }

    reverse_proxy backend:3000
}
```

### Coraza Configuration

Edit `coraza.conf` to customize OWASP rules and add custom protection rules.

### Custom WAF Configuration

Custom rules are managed via:
- Dashboard UI: `http://your-server:8080`
- API endpoints:
  - `POST /api/waf/custom-rules` - Create custom rule
  - `POST /api/waf/blocklist` - Block IP
  - `POST /api/waf/whitelist` - Whitelist IP

## Testing

### Test OWASP Protection (Layer 1)

```bash
# Test XSS blocking
curl -k 'https://your-server/test?q=<script>alert(1)</script>'
# Expected: 403 Forbidden

# Test SQL Injection blocking
curl -k 'https://your-server/test?id=1%20OR%201=1'
# Expected: 403 Forbidden
```

### Test Custom WAF (Layer 2)

```bash
# Block an IP via API
curl -X POST http://localhost:8081/api/waf/blocklist \
  -H "Content-Type: application/json" \
  -d '{"ip":"192.168.1.100","reason":"Test block"}'

# Test blocked IP
curl -k https://your-server/ --interface 192.168.1.100
# Expected: 403 Forbidden
```

## Monitoring

### Logs

```bash
# Layer 1 (Coraza) logs
tail -f /var/log/caddy/coraza_audit.log

# Layer 2 (Custom WAF) logs
tail -f /var/log/caddy/waf.log

# Caddy access logs
tail -f /var/log/caddy/access.log
```

### Dashboard

Access real-time monitoring:
```
http://your-server:8080
```

Features:
- Threat statistics
- Blocked IPs
- Custom rules management
- Real-time alerts
- Export logs (JSON, CSV, PDF)

## Documentation

- **Quick Start**: [DUAL-WAF-QUICKSTART.md](DUAL-WAF-QUICKSTART.md)
- **Full Deployment Guide**: [CORAZA-DEPLOYMENT.md](CORAZA-DEPLOYMENT.md)

## Project Structure

```
waf/
├── cmd/caddy-waf/          # Main entry point
├── internal/
│   ├── detector/           # Attack detectors
│   ├── logger/             # Logging system
│   ├── blocklist/          # IP blocklist management
│   ├── ipextract/          # IP intelligence
│   ├── rules/              # Rules engine
│   └── metrics/            # Metrics collection
├── pkg/waf/                # Caddy middleware
├── tests/                  # Tests
├── Caddyfile               # Caddy configuration
├── coraza.conf             # Coraza WAF configuration
├── build-caddy-coraza.sh   # Build script
└── deploy-coraza.sh        # Deployment script
```

## Development

### Running Tests

```bash
# Run all tests
go test ./...

# Run specific detector tests
go test ./internal/detector -run TestXSS

# Run with coverage
go test -cover ./...
```

### Adding Custom Detectors

1. Create detector in `internal/detector/`
2. Implement detection logic
3. Register in `detector.go`
4. Add tests

## Troubleshooting

### WAF Not Blocking

```bash
# Verify modules loaded
caddy list-modules | grep -E '(coraza|waf)'

# Check Coraza config
ls -la /etc/caddy/waf/coraza.conf

# Check OWASP rules
ls -la /etc/caddy/waf/coreruleset/rules/
```

### False Positives

If legitimate traffic is blocked:
1. Whitelist IP via Dashboard
2. Adjust Coraza rules in `coraza.conf`
3. Create exception in Custom WAF

### Performance Issues

1. Check log file sizes
2. Review enabled rules
3. Adjust Coraza debug level
4. Monitor system resources

## Support

- Check logs: `/var/log/caddy/`
- Validate config: `caddy validate --config /etc/caddy/Caddyfile`
- Service status: `systemctl status caddy`

## License

See root LICENSE file.
