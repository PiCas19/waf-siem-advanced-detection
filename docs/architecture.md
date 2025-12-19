# Architecture Documentation

## System Overview

The WAF-SIEM Advanced Detection system implements a **dual-layer Web Application Firewall** architecture with integrated SIEM capabilities for comprehensive threat detection and monitoring.

### High-Level Architecture

```
┌──────────────────────────────────────────────────────────┐
│                     Internet / WAN                        │
└────────────────────────┬─────────────────────────────────┘
                         │ HTTPS (TLS 1.2/1.3)
                         │
┌────────────────────────▼─────────────────────────────────┐
│                  Caddy Web Server                         │
│  ┌────────────────────────────────────────────────────┐  │
│  │ Layer 1: Coraza WAF (OWASP ModSecurity CRS)       │  │
│  │ - 200+ OWASP rules                                 │  │
│  │ - XSS, SQLi, RCE, Path Traversal                   │  │
│  │ - Scanner detection                                │  │
│  │ - Protocol attacks                                 │  │
│  └──────────────────────┬─────────────────────────────┘  │
│                         │ PASS                            │
│  ┌──────────────────────▼─────────────────────────────┐  │
│  │ Layer 2: Custom WAF (Business Logic)              │  │
│  │ 1. Whitelist Check → Bypass all if whitelisted    │  │
│  │ 2. Blocklist Check → Block if blocklisted         │  │
│  │ 3. Threat Detection:                               │  │
│  │    - Default Rules (~100 builtin)                  │  │
│  │    - Custom Rules (database)                       │  │
│  │    - Manual Block Rules (priority)                 │  │
│  │ 4. IP Intelligence (Tailscale, DMZ, HMAC)         │  │
│  │ 5. Logging & Events → API Backend                 │  │
│  └──────────────────────┬─────────────────────────────┘  │
│                         │ PASS                            │
└────────────────────────┬─────────────────────────────────┘
                         │
         ┌───────────────┴────────────────┐
         │                                 │
┌────────▼───────┐               ┌────────▼────────────┐
│   Backend      │               │   API Backend (Go)   │
│  Application   │               │  - JWT Auth          │
│  (Protected)   │               │  - Database (SQLite) │
│                │               │  - WebSocket         │
│                │               │  - SIEM Integration  │
└────────────────┘               └──────┬───────────────┘
                                        │
                                ┌───────▼──────────┐
                                │   Dashboard      │
                                │  (React + TS)    │
                                │  - Monitoring    │
                                │  - Rules Mgmt    │
                                │  - Analytics     │
                                └──────────────────┘
```

---

## Component Details

### 1. Dual-Layer WAF

#### Layer 1: Coraza WAF (OWASP ModSecurity Core Rule Set)

**Location**: Caddy middleware (`coraza_waf`)

**Purpose**: Industry-standard web application firewall with OWASP Core Rule Set v4.7.0

**Capabilities**:
- **200+ OWASP Rules**: Automatic protection against known attack patterns
- **Attack Types Detected**:
  - Cross-Site Scripting (XSS)
  - SQL Injection (SQLi)
  - Remote Code Execution (RCE)
  - Path Traversal / LFI
  - Command Injection
  - Scanner Detection (Nikto, SQLMap, etc.)
  - Protocol Attacks
  - Data Leakage Prevention
  - OWASP Top 10 Coverage

**Configuration**: `/etc/caddy/waf/coraza.conf`

**Execution Order**: **First** in the request chain

**Logging**: Disabled by default (handled by Layer 2)

**Key Files**:
- `waf/configs/coraza.conf` - Main configuration
- `/etc/caddy/waf/coreruleset/` - OWASP CRS rules

#### Layer 2: Custom WAF (Business Logic Protection)

**Location**: Caddy middleware (`custom_waf`)

**Purpose**: Custom business logic protection with dynamic rule management

**3 Rule Types**:

1. **Default Rules** (~100 builtin Go detectors):
   - XSS (Cross-Site Scripting)
   - SQL Injection (MySQL, PostgreSQL, MSSQL)
   - SSRF (Server-Side Request Forgery)
   - SSTI (Server-Side Template Injection)
   - XXE (XML External Entity)
   - NoSQL Injection (MongoDB, Redis)
   - LDAP Injection
   - Command Injection
   - Path Traversal
   - Prototype Pollution
   - CRLF Injection

2. **Custom Rules** (database-managed, regex-based):
   - Created via Dashboard UI
   - Stored in database
   - Dynamically loaded without restart
   - Supports regex patterns
   - Severity levels: low, medium, high, critical

3. **Manual Block Rules** (high-priority):
   - Created when manually blocking a threat
   - Immediate IP/pattern blocking
   - Highest priority
   - Bypass other rules

**IP Intelligence Features**:
- **Whitelist/Blocklist Management**: Dynamic IP allow/deny lists
- **Tailscale Detection**: Identify requests from Tailscale network (100.64.0.0/10)
- **DMZ Detection**: Identify requests from DMZ network
- **HMAC Signature Validation**: Optional request signature verification

**Blocking Actions**:
- `block` (403 Forbidden)
- `drop` (close connection)
- `redirect` (302 redirect)
- `challenge` (Cloudflare Turnstile CAPTCHA)

**Configuration**: `Caddyfile` (`custom_waf` directive)

**Execution Order**: **After** Coraza WAF, **before** reverse_proxy

**Logging**: Structured JSON logs to `/var/log/caddy/waf.log` or `/var/log/caddy/waf_wan.log`, `/var/log/caddy/waf_lan.log`

**Key Files**:
- `waf/pkg/waf/middleware.go` - Main middleware
- `waf/internal/detector/*.go` - Attack detectors
- `waf/internal/rules/engine.go` - Rules engine
- `waf/internal/blocklist/` - IP blocklist management

---

### 2. API Backend (Go + Gin Framework)

**Location**: `api/`

**Purpose**: RESTful API for dashboard, WAF integration, and data management

**Technology Stack**:
- **Framework**: Gin (HTTP router)
- **Database**: GORM + SQLite (production: PostgreSQL ready)
- **Authentication**: JWT (golang-jwt/jwt)
- **WebSocket**: Gorilla WebSocket (real-time updates)

**Responsibilities**:
- User authentication (JWT + optional 2FA)
- Custom rule CRUD operations
- Log storage and retrieval
- IP blocklist/whitelist management
- Statistics and analytics
- False positive tracking
- Audit logging
- Export functionality (JSON, CSV, PDF)
- Real-time threat notifications via WebSocket

**Key Directories**:
```
api/
├── cmd/api-server/        # Main entry point
├── internal/
│   ├── api/               # HTTP handlers & router
│   ├── auth/              # JWT & 2FA authentication
│   ├── database/          # Database models & migrations
│   ├── repository/        # Data access layer
│   ├── service/           # Business logic
│   ├── middleware/        # CORS, rate limiting, context
│   ├── websocket/         # Real-time notifications
│   ├── geoip/             # IP geolocation
│   ├── mailer/            # Email notifications
│   └── config/            # Configuration management
└── docs/                  # Swagger API docs
```

**Database Models**:
- `User` - Dashboard users with roles (admin, analyst, viewer)
- `Rule` - Custom WAF detection rules
- `Log` - Security event logs
- `BlockedIP` - IP blocklist with expiration
- `WhitelistedIP` - IP whitelist
- `AuditLog` - User activity audit trail
- `FalsePositive` - False positive reports

**API Endpoints**: See [API Reference](api-reference.md)

---

### 3. Dashboard (React + TypeScript)

**Location**: `dashboard/`

**Purpose**: Web-based user interface for monitoring and management

**Technology Stack**:
- **Framework**: React 18 + TypeScript
- **Build Tool**: Vite
- **Styling**: Tailwind CSS
- **Charts**: Recharts
- **HTTP Client**: Axios
- **Router**: React Router v6

**Features**:
- **Authentication**: JWT-based login with optional 2FA
- **Real-time Monitoring**: WebSocket for live threat updates
- **Dashboard**: Statistics, charts, threat trends
- **Log Viewer**: Filterable, searchable security logs
- **Rule Management**: Create, edit, delete custom rules
- **IP Management**: Blocklist and whitelist management
- **False Positives**: Report and track false positives
- **User Management**: Admin-only user CRUD
- **Export**: Logs export to JSON, CSV, PDF
- **Responsive Design**: Mobile-friendly interface

**Key Directories**:
```
dashboard/
├── src/
│   ├── components/        # Reusable UI components
│   ├── pages/             # Page components
│   ├── hooks/             # Custom React hooks
│   ├── services/          # API client
│   ├── context/           # React context (auth, theme)
│   ├── types/             # TypeScript types
│   └── utils/             # Helper functions
└── public/                # Static assets
```

---

## Data Flow

### Request Processing Flow

```
1. Client Request → Caddy Server
2. Layer 1 (Coraza WAF) inspects request against OWASP rules
   ├─ If threat detected → Block (403) + Log
   └─ If clean → Continue to Layer 2
3. Layer 2 (Custom WAF) applies business logic:
   ├─ Check whitelist → If whitelisted: Allow (bypass all checks)
   ├─ Check blocklist → If blocked: Block (403)
   ├─ Run threat detection (Default + Custom + Manual rules)
   ├─ If threat detected:
   │  ├─ Log event to file (/var/log/caddy/waf.log)
   │  ├─ Send event to API (/api/waf/event)
   │  └─ Take action (block/drop/redirect/challenge)
   └─ If clean: Continue to backend
4. Backend Application processes request
5. Response → Client
```

### Dashboard Interaction Flow

```
1. User logs in → API validates credentials → Returns JWT token
2. Dashboard stores token in localStorage
3. User navigates to dashboard:
   ├─ GET /api/stats (with JWT) → API queries database → Returns stats
   └─ WebSocket connection (/ws?token=JWT) established for real-time updates
4. WAF detects threat:
   ├─ Layer 2 logs to file
   ├─ POST /api/waf/event → API stores in database
   └─ WebSocket broadcasts event → Dashboard shows real-time alert
5. User creates custom rule:
   ├─ POST /api/rules (with JWT) → API validates & stores in DB
   └─ Custom WAF fetches updated rules → GET /api/waf/custom-rules
```

### WAF Rules Synchronization

```
1. Admin creates custom rule via Dashboard
   └─ POST /api/rules → Database stores rule
2. Custom WAF middleware periodically fetches rules (every 60 seconds):
   └─ GET /api/waf/custom-rules → Returns latest rules from DB
3. New request arrives:
   └─ Custom WAF applies newly fetched rules
```

### IP Blocklist Synchronization

```
1. Analyst blocks IP via Dashboard
   └─ POST /api/blocklist → Database adds IP + creates manual block rule
2. Custom WAF fetches blocklist on startup and every 60 seconds:
   └─ GET /api/waf/blocklist → Returns blocked IPs
3. Request from blocked IP arrives:
   └─ Custom WAF blocks immediately (before rule execution)
```

---

## Security Architecture

### Defense in Depth

The system implements multiple security layers:

```
┌─────────────────────────────────────────────────┐
│ Layer 1: Network Security                       │
│ - Tailscale Zero Trust Network (optional)       │
│ - Firewall (OPNsense / DMZ)                     │
│ - TLS 1.2/1.3 encryption                        │
└─────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────┐
│ Layer 2: Coraza WAF (OWASP CRS)                │
│ - 200+ OWASP rules                              │
│ - Attack pattern detection                      │
│ - Evasion techniques detection                  │
└─────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────┐
│ Layer 3: Custom WAF (Business Logic)           │
│ - IP whitelist/blocklist                        │
│ - Custom detection rules                        │
│ - IP intelligence                               │
│ - HMAC signature validation (optional)          │
└─────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────┐
│ Layer 4: Application Security                   │
│ - JWT authentication                            │
│ - Role-based access control (RBAC)             │
│ - Input validation                              │
│ - SQL injection prevention (parameterized)      │
└─────────────────────────────────────────────────┘
```

### Zero Trust Principles

1. **Identity-Based Authentication**:
   - JWT tokens for API access
   - Optional 2FA (TOTP)
   - Password reset via email

2. **Least Privilege Access**:
   - Role-based permissions (admin, analyst, viewer)
   - Granular endpoint permissions
   - Audit logging of all actions

3. **Continuous Verification**:
   - JWT token expiration (default: 24h)
   - Real-time blocklist updates
   - Session monitoring

4. **Encryption Everywhere**:
   - TLS 1.2/1.3 for HTTPS
   - Secure password hashing (bcrypt)
   - JWT signed with HMAC-SHA256

5. **No Exposed Ports** (optional):
   - Tailscale Funnel for WAN access
   - No public IP exposure
   - Encrypted tunnels

---

## Performance Optimization

### Caching & Efficiency

1. **Rules Caching**:
   - Custom WAF caches rules for 60 seconds
   - Reduces database queries
   - Background refresh

2. **Database Connection Pooling**:
   - Max open connections: 25
   - Max idle connections: 5
   - Connection lifetime: 5 minutes

3. **TLS Optimization**:
   - TLS 1.3 with 0-RTT
   - Session resumption
   - Modern ciphers (AES-GCM, ChaCha20-Poly1305)

4. **Compression**:
   - Gzip/Zstd for text content
   - Brotli for static assets

5. **Log Management**:
   - Structured JSON logging
   - Log rotation (daily, 30 days retention)
   - Async log writing

### Scalability Considerations

**Horizontal Scaling**:
- Stateless API design (JWT-based)
- SQLite → PostgreSQL migration ready
- Load balancer friendly (no session affinity needed)

**Vertical Scaling**:
- Configurable database connection pools
- Adjustable rate limits
- Memory-efficient rule engine

---

## Logging & Monitoring

### Log Types

1. **WAF Logs** (`/var/log/caddy/waf.log`):
   ```json
   {
     "timestamp": "2025-12-19T10:00:00Z",
     "client_ip": "192.168.1.100",
     "country": "IT",
     "method": "GET",
     "url": "/api/search?q=<script>alert(1)</script>",
     "threat_type": "XSS",
     "severity": "high",
     "rule_matched": "Default XSS Rule #5",
     "action_taken": "blocked"
   }
   ```

2. **Coraza Audit Logs** (optional, `/var/log/caddy/coraza_audit.log`):
   - Disabled by default
   - Can be enabled for OWASP rule debugging

3. **API Logs** (stdout or file):
   - Structured JSON logs
   - Request/response logging
   - Error tracking

4. **Audit Logs** (database):
   - User actions tracking
   - Administrative changes
   - Login attempts

### SIEM Integration

**Log Forwarding Options**:

1. **Filebeat → Elasticsearch**:
   ```yaml
   # filebeat.yml
   filebeat.inputs:
     - type: log
       paths:
         - /var/log/caddy/waf.log
       json.keys_under_root: true
   ```

2. **Fluent Bit → Graylog**:
   - Real-time log forwarding
   - Structured JSON parsing

3. **Custom Webhook**:
   - POST to SIEM API endpoint
   - Configurable in Custom WAF

---

## Deployment Architectures

### Development Setup

```
┌─────────────────┐
│  Localhost      │
│  - Caddy :443   │
│  - API :8081    │
│  - Dashboard    │
│    :3000        │
└─────────────────┘
```

### Production Setup (Single Server)

```
┌────────────────────────────────────┐
│         Production Server          │
│  ┌──────────────────────────────┐  │
│  │  Caddy (systemd service)     │  │
│  │  - Port 443 (HTTPS)          │  │
│  │  - Dual-Layer WAF            │  │
│  └──────────────────────────────┘  │
│  ┌──────────────────────────────┐  │
│  │  API Backend (systemd)       │  │
│  │  - Port 8081 (internal)      │  │
│  └──────────────────────────────┘  │
│  ┌──────────────────────────────┐  │
│  │  Dashboard (served by Caddy) │  │
│  │  - /var/www/html/dashboard   │  │
│  └──────────────────────────────┘  │
│  ┌──────────────────────────────┐  │
│  │  Database (SQLite)           │  │
│  │  - /var/lib/waf/waf.db       │  │
│  └──────────────────────────────┘  │
└────────────────────────────────────┘
```

### Production Setup (Multi-Tier)

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Caddy WAF  │────▶│  API Backend │────▶│  PostgreSQL  │
│   (Layer 1+2)│     │   (Go API)   │     │   Database   │
│   Port 443   │     │   Port 8081  │     │   Port 5432  │
└──────┬───────┘     └──────────────┘     └──────────────┘
       │
       │ Serves
       ▼
┌──────────────┐
│  Dashboard   │
│  (React SPA) │
│  Static Files│
└──────────────┘
```

---

## Technology Stack Summary

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Web Server** | Caddy 2.x | Reverse proxy, TLS, WAF host |
| **Layer 1 WAF** | Coraza + OWASP CRS v4.7 | Industry-standard protection |
| **Layer 2 WAF** | Custom Go middleware | Business logic protection |
| **API Backend** | Go + Gin framework | RESTful API |
| **Database** | SQLite (dev) / PostgreSQL (prod) | Data persistence |
| **Dashboard** | React 18 + TypeScript + Tailwind | Web UI |
| **Authentication** | JWT + TOTP (2FA) | Secure access |
| **Logging** | Structured JSON | SIEM integration |
| **Network** | Tailscale (optional) | Zero Trust networking |

---

## Future Enhancements

1. **Machine Learning Integration**:
   - Anomaly detection
   - Behavioral analysis
   - Automated threat scoring

2. **Advanced Analytics**:
   - Threat intelligence feeds
   - Geographic heatmaps
   - Attack correlation

3. **Distributed Deployment**:
   - Multi-node API cluster
   - Distributed rate limiting
   - Centralized rule management

4. **Enhanced Reporting**:
   - Scheduled PDF reports
   - Email alerts
   - Compliance reports (PCI-DSS, GDPR)

5. **API Rate Limiting**:
   - Per-IP rate limiting
   - Per-endpoint limits
   - DDoS protection

---

## References

- [OWASP ModSecurity Core Rule Set](https://owasp.org/www-project-modsecurity-core-rule-set/)
- [Caddy Web Server Documentation](https://caddyserver.com/docs/)
- [Coraza WAF Documentation](https://coraza.io/)
- [Configuration Guide](configuration.md)
- [API Reference](api-reference.md)
- [Installation Guide](installation.md)
