# Configuration Guide

Complete configuration reference for WAF-SIEM Advanced Detection system.

## Table of Contents

1. [API Backend Configuration](#api-backend-configuration)
2. [WAF Middleware Configuration](#waf-middleware-configuration)
3. [Coraza WAF Configuration](#coraza-waf-configuration)
4. [Database Configuration](#database-configuration)
5. [Dashboard Configuration](#dashboard-configuration)
6. [Production Deployment](#production-deployment)

---

## API Backend Configuration

The API backend is configured via environment variables. Create a `.env` file in the `api/` directory.

### Environment Variables

#### Server Configuration

```bash
# Server settings
PORT=8081                          # API server port
SERVER_HOST=0.0.0.0               # Bind address (0.0.0.0 for all interfaces)
SERVER_SHUTDOWN_TIMEOUT=30s       # Graceful shutdown timeout
```

#### Database Configuration

```bash
# Database settings
DB_PATH=./waf.db                  # SQLite database file path
DB_MAX_OPEN_CONNS=25              # Maximum open database connections
DB_MAX_IDLE_CONNS=5               # Maximum idle connections in pool
DB_CONN_MAX_LIFETIME=5m           # Maximum connection lifetime
DB_LOG_QUERIES=false              # Log SQL queries (debug only)
```

#### Authentication Configuration

```bash
# JWT and Auth settings
JWT_SECRET=your-secret-key-change-me-in-production  # JWT signing secret (CHANGE THIS!)
TOKEN_EXPIRATION=24h              # JWT token expiration time
OTP_WINDOW=30s                    # OTP code valid time window
```

**Security Note:** Always use a strong, randomly generated JWT secret in production:
```bash
# Generate secure JWT secret
openssl rand -base64 64
```

#### Logging Configuration

```bash
# Logger settings
LOG_LEVEL=info                    # Log level: debug, info, warn, error
LOG_OUTPUT=stdout                 # Log output: stdout, stderr, or file path
```

**Log Levels:**
- `debug`: Detailed debugging information
- `info`: General informational messages
- `warn`: Warning messages
- `error`: Error messages only

#### CORS Configuration

```bash
# CORS settings
CORS_ALLOWED_ORIGINS=http://localhost:3000,https://dashboard.example.com
```

**Default CORS Settings:**
- Allowed Methods: `GET, POST, PUT, DELETE, PATCH, OPTIONS`
- Allowed Headers: `Accept, Authorization, Content-Type, X-CSRF-Token`
- Exposed Headers: `Link`
- Max Age: `300` seconds
- Allow Credentials: `true`

#### Rate Limiting Configuration

```bash
# Rate limiting settings
RATE_LIMIT_ENABLED=true           # Enable/disable rate limiting
RATE_LIMIT_RPS=100                # Requests per second
RATE_LIMIT_BURST=150              # Burst size
RATE_LIMIT_WINDOW=1s              # Rate limit window duration
```

#### Email Configuration (Optional)

For password reset and user invitations:

```bash
# SMTP settings
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM=noreply@example.com
SMTP_FROM_NAME=WAF Security System
```

#### GeoIP Configuration (Optional)

For IP geolocation features:

```bash
# MaxMind GeoIP settings
MAXMIND_LICENSE_KEY=your-maxmind-license-key
```

Get a free license key from [MaxMind](https://www.maxmind.com/en/geolite2/signup).

### Complete .env Example

```bash
# Server
PORT=8081
SERVER_HOST=0.0.0.0
SERVER_SHUTDOWN_TIMEOUT=30s

# Database
DB_PATH=./waf.db
DB_MAX_OPEN_CONNS=25
DB_MAX_IDLE_CONNS=5
DB_CONN_MAX_LIFETIME=5m
DB_LOG_QUERIES=false

# Authentication
JWT_SECRET=replace-with-secure-random-secret-minimum-64-characters
TOKEN_EXPIRATION=24h
OTP_WINDOW=30s

# Logging
LOG_LEVEL=info
LOG_OUTPUT=stdout

# CORS
CORS_ALLOWED_ORIGINS=http://localhost:3000,https://dashboard.example.com

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_RPS=100
RATE_LIMIT_BURST=150
RATE_LIMIT_WINDOW=1s

# Email (Optional)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM=noreply@example.com
SMTP_FROM_NAME=WAF Security System

# GeoIP (Optional)
MAXMIND_LICENSE_KEY=your-maxmind-license-key
```

---

## WAF Middleware Configuration

The WAF middleware is configured in the `Caddyfile`.

### Basic Caddyfile Structure

```caddy
{
    # Global options
    order custom_waf first
    order coraza_waf before reverse_proxy
}

:443 {
    # Layer 1: Coraza WAF (OWASP CRS)
    coraza_waf {
        directives `
            Include /etc/caddy/waf/coraza.conf
        `
    }

    # Layer 2: Custom WAF
    custom_waf {
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

        # HMAC Signature Validation (Optional)
        enable_hmac_signature_validation false
        hmac_shared_secret "your-hmac-secret"

        trusted_proxies 127.0.0.1 ::1
    }

    # Your application
    reverse_proxy backend:3000
}
```

### Custom WAF Directives

#### Required Directives

| Directive | Type | Description | Example |
|-----------|------|-------------|---------|
| `log_file` | string | Path to WAF log file | `/var/log/caddy/waf.log` |
| `block_mode` | bool | Enable blocking (vs log-only mode) | `true` |
| `api_endpoint` | string | API backend base URL | `http://localhost:8081/api` |

#### Optional Directives

| Directive | Type | Default | Description |
|-----------|------|---------|-------------|
| `rules_endpoint` | string | - | Custom rules API endpoint |
| `blocklist_endpoint` | string | - | Blocklist API endpoint |
| `whitelist_endpoint` | string | - | Whitelist API endpoint |
| `enable_tailscale_detection` | bool | `false` | Detect Tailscale network IPs |
| `tailscale_networks` | CIDR | `100.64.0.0/10` | Tailscale network range |
| `enable_dmz_detection` | bool | `false` | Detect DMZ network IPs |
| `dmz_networks` | CIDR | - | DMZ network range |
| `enable_hmac_signature_validation` | bool | `false` | Validate HMAC signatures |
| `hmac_shared_secret` | string | - | HMAC shared secret key |
| `trusted_proxies` | list | `127.0.0.1 ::1` | Trusted proxy IP addresses |

### WAF Configuration Modes

#### 1. Detection-Only Mode

Logs threats without blocking:

```caddy
custom_waf {
    log_file /var/log/caddy/waf.log
    block_mode false              # Only log, don't block
    api_endpoint http://localhost:8081/api
}
```

#### 2. Full Protection Mode

Blocks threats with custom rules:

```caddy
custom_waf {
    log_file /var/log/caddy/waf.log
    block_mode true
    api_endpoint http://localhost:8081/api
    rules_endpoint http://localhost:8081/api/waf/custom-rules
    blocklist_endpoint http://localhost:8081/api/waf/blocklist
    whitelist_endpoint http://localhost:8081/api/waf/whitelist
}
```

#### 3. Advanced Mode with IP Intelligence

Full protection with Tailscale and DMZ detection:

```caddy
custom_waf {
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

    trusted_proxies 127.0.0.1 ::1 100.64.0.0/10
}
```

#### 4. Extreme Mode with HMAC Validation

Maximum security with request signature validation:

```caddy
custom_waf {
    log_file /var/log/caddy/waf.log
    block_mode true
    api_endpoint http://localhost:8081/api
    rules_endpoint http://localhost:8081/api/waf/custom-rules
    blocklist_endpoint http://localhost:8081/api/waf/blocklist
    whitelist_endpoint http://localhost:8081/api/waf/whitelist

    # HMAC Signature Validation
    enable_hmac_signature_validation true
    hmac_shared_secret "your-secret-key-minimum-32-characters"

    # IP Intelligence
    enable_tailscale_detection true
    tailscale_networks 100.64.0.0/10
    enable_dmz_detection true
    dmz_networks 172.16.216.0/24

    trusted_proxies 127.0.0.1 ::1 100.64.0.0/10
}
```

### Reusable Configuration Snippets

Use snippets for consistent configuration across multiple sites:

```caddy
{
    order custom_waf first
    order coraza_waf before reverse_proxy
}

# Define reusable WAF configuration
(waf_protection) {
    coraza_waf {
        directives `
            Include /etc/caddy/waf/coraza.conf
        `
    }

    custom_waf {
        log_file /var/log/caddy/waf.log
        block_mode true
        api_endpoint http://localhost:8081/api
        rules_endpoint http://localhost:8081/api/waf/custom-rules
        blocklist_endpoint http://localhost:8081/api/waf/blocklist
        whitelist_endpoint http://localhost:8081/api/waf/whitelist
    }
}

# Use in multiple sites
:443 {
    import waf_protection
    reverse_proxy app1:3000
}

:8443 {
    import waf_protection
    reverse_proxy app2:4000
}
```

---

## Coraza WAF Configuration

Coraza WAF is configured via `coraza.conf` file.

### Basic coraza.conf

```apache
# Basic Coraza Configuration
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecAuditEngine Off

# Include OWASP Core Rule Set
Include /etc/caddy/waf/coreruleset/crs-setup.conf
Include /etc/caddy/waf/coreruleset/rules/*.conf

# Custom rules
SecRule REQUEST_HEADERS:User-Agent "@rx (bot|crawler|spider)" \
    "id:1001,phase:1,deny,status:403,msg:'Blocked bot'"
```

### Important Coraza Directives

| Directive | Values | Description |
|-----------|--------|-------------|
| `SecRuleEngine` | On/Off/DetectionOnly | Enable rule engine |
| `SecRequestBodyAccess` | On/Off | Inspect request body |
| `SecAuditEngine` | On/Off/RelevantOnly | Enable audit logging |
| `SecAuditLog` | path | Audit log file path |

### Audit Logging

**Note:** By default, Coraza audit logging is disabled to prevent duplicate logs. All logging is handled by Custom WAF layer.

To enable Coraza audit logging:

```apache
SecAuditEngine On
SecAuditLog /var/log/caddy/coraza_audit.log
SecAuditLogFormat JSON
SecAuditLogType Serial
```

---

## Database Configuration

### SQLite (Default)

Default database is SQLite stored in `waf.db`:

```bash
DB_PATH=./waf.db
```

**Production Recommendations:**
- Store database on persistent volume
- Regular backups with `sqlite3 waf.db ".backup backup.db"`
- Use WAL mode for better concurrency

### Database Schema

The database is automatically migrated on startup. Tables include:

- `users` - Dashboard users
- `rules` - Custom WAF rules
- `logs` - Security event logs
- `blocked_ips` - IP blocklist
- `whitelisted_ips` - IP whitelist
- `audit_logs` - User activity audit logs
- `false_positives` - False positive reports

---

## Dashboard Configuration

The React dashboard is configured via environment variables in `dashboard/.env`.

### Dashboard Environment Variables

```bash
# API Backend URL
VITE_API_URL=http://localhost:8081

# WebSocket URL
VITE_WS_URL=ws://localhost:8081/ws

# App Configuration
VITE_APP_NAME=WAF Security Dashboard
VITE_APP_VERSION=1.0.0

# Feature Flags
VITE_ENABLE_2FA=true
VITE_ENABLE_EXPORT=true
```

### Build Configuration

For production deployment:

```bash
# Build for production
cd dashboard
npm run build

# Output will be in dashboard/dist/
```

Then serve the `dist/` directory with any web server (Nginx, Apache, Caddy).

---

## Production Deployment

### Security Checklist

- [ ] Change `JWT_SECRET` to a strong random value
- [ ] Set `block_mode true` in WAF configuration
- [ ] Enable HTTPS with valid SSL certificates
- [ ] Configure `trusted_proxies` correctly
- [ ] Set strong database file permissions (`chmod 600 waf.db`)
- [ ] Enable audit logging
- [ ] Configure email for alerts
- [ ] Set up log rotation
- [ ] Enable rate limiting
- [ ] Whitelist your internal IPs
- [ ] Test backup and restore procedures

### Recommended Production Settings

#### API Backend (.env)

```bash
PORT=8081
SERVER_HOST=0.0.0.0
JWT_SECRET=$(openssl rand -base64 64)
TOKEN_EXPIRATION=12h
LOG_LEVEL=info
LOG_OUTPUT=/var/log/waf-api/api.log
RATE_LIMIT_ENABLED=true
RATE_LIMIT_RPS=100
DB_PATH=/var/lib/waf/waf.db
```

#### WAF Middleware (Caddyfile)

```caddy
{
    email admin@example.com
    auto_https on

    order custom_waf first
    order coraza_waf before reverse_proxy
}

:443 {
    tls {
        protocols tls1.2 tls1.3
    }

    coraza_waf {
        directives `
            Include /etc/caddy/waf/coraza.conf
        `
    }

    custom_waf {
        log_file /var/log/caddy/waf.log
        block_mode true
        api_endpoint http://localhost:8081/api
        rules_endpoint http://localhost:8081/api/waf/custom-rules
        blocklist_endpoint http://localhost:8081/api/waf/blocklist
        whitelist_endpoint http://localhost:8081/api/waf/whitelist
        trusted_proxies 127.0.0.1 ::1
    }

    reverse_proxy backend:3000
}
```

### Log Rotation

Configure log rotation for WAF and API logs:

```bash
# /etc/logrotate.d/waf-logs
/var/log/caddy/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 caddy caddy
    sharedscripts
    postrotate
        systemctl reload caddy
    endscript
}

/var/log/waf-api/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 waf-api waf-api
}
```

### Monitoring

Monitor these key metrics:

- Request rate (requests/second)
- Threat detection rate
- Block rate
- API response time
- Database size
- Log file sizes
- CPU and memory usage

### Backup Strategy

```bash
# Daily database backup
0 2 * * * /usr/local/bin/backup-waf-db.sh

# backup-waf-db.sh
#!/bin/bash
DB_PATH="/var/lib/waf/waf.db"
BACKUP_DIR="/var/backups/waf"
DATE=$(date +%Y%m%d)
sqlite3 $DB_PATH ".backup $BACKUP_DIR/waf-$DATE.db"
find $BACKUP_DIR -name "waf-*.db" -mtime +30 -delete
```

---

## Configuration Validation

### Test WAF Configuration

```bash
# Validate Caddyfile syntax
caddy validate --config /etc/caddy/Caddyfile

# Test WAF blocking
curl 'https://your-server/test?q=<script>alert(1)</script>'
# Expected: 403 Forbidden

# Test legitimate request
curl 'https://your-server/test?q=hello'
# Expected: 200 OK
```

### Test API Configuration

```bash
# Check API health
curl http://localhost:8081/api/stats

# Test authentication
curl -X POST http://localhost:8081/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"your-password"}'
```

### Verify Logging

```bash
# Check WAF logs
tail -f /var/log/caddy/waf.log | jq .

# Check API logs
tail -f /var/log/waf-api/api.log

# Check Coraza logs (if enabled)
tail -f /var/log/caddy/coraza_audit.log | jq .
```

---

## Troubleshooting

### Common Configuration Issues

**Issue:** WAF not blocking threats
- Check `block_mode` is set to `true`
- Verify Coraza rules are loaded: `ls /etc/caddy/waf/coreruleset/rules/`
- Check Caddyfile syntax: `caddy validate`

**Issue:** API not starting
- Verify `JWT_SECRET` is set
- Check database path exists and is writable
- Verify port 8081 is not in use: `lsof -i :8081`

**Issue:** Dashboard can't connect to API
- Check `VITE_API_URL` matches API server address
- Verify CORS settings allow dashboard origin
- Check browser console for CORS errors

**Issue:** High memory usage
- Reduce `DB_MAX_OPEN_CONNS`
- Enable log rotation
- Check for memory leaks in custom rules

---

## Environment-Specific Configuration

### Development

```bash
LOG_LEVEL=debug
DB_LOG_QUERIES=true
RATE_LIMIT_ENABLED=false
CORS_ALLOWED_ORIGINS=http://localhost:3000
```

### Staging

```bash
LOG_LEVEL=info
RATE_LIMIT_ENABLED=true
RATE_LIMIT_RPS=100
CORS_ALLOWED_ORIGINS=https://staging.example.com
```

### Production

```bash
LOG_LEVEL=warn
RATE_LIMIT_ENABLED=true
RATE_LIMIT_RPS=1000
TOKEN_EXPIRATION=12h
CORS_ALLOWED_ORIGINS=https://dashboard.example.com
```
