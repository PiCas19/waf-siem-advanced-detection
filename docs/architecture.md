# Architecture Documentation

## System Overview

The WAF-SIEM system consists of four main components:
```
┌─────────────────────────────────────────────────┐
│                   Internet                       │
└─────────────────────┬───────────────────────────┘
                      │
                      │ HTTPS (Tailscale Funnel)
                      │
┌─────────────────────▼───────────────────────────┐
│            Caddy + WAF Middleware               │
│  - Request inspection                           │
│  - Threat detection                             │
│  - Logging                                       │
│  - Blocking                                      │
└──────────┬─────────────────────┬─────────────────┘
           │                     │
           │                     │
┌──────────▼──────────┐  ┌───────▼──────────────┐
│   Dashboard (React)  │  │   API Backend (Go)    │
│  - User interface    │  │  - JWT auth           │
│  - Real-time updates │  │  - Database           │
│  - Rule management   │  │  - WebSocket          │
└──────────────────────┘  └───────┬───────────────┘
                                  │
                          ┌───────▼───────────┐
                          │  Database (SQLite) │
                          │  - Users           │
                          │  - Rules           │
                          │  - Logs            │
                          │  - Blocklist       │
                          └────────────────────┘
```

## Component Details

### 1. WAF Middleware (Go)

**Location**: `waf/`

**Responsibilities**:
- HTTP request inspection
- Multi-attack detection (XSS, SQLi, LFI, RFI, Command Injection)
- Structured JSON logging
- Request blocking in block mode
- Integration with Caddy server

**Key Files**:
- `pkg/waf/middleware.go` - Main middleware handler
- `internal/detector/*.go` - Attack detectors
- `internal/logger/logger.go` - Logging system

### 2. Dashboard (React + TypeScript)

**Location**: `dashboard/`

**Responsibilities**:
- User interface for monitoring
- Real-time threat visualization
- Custom rule management
- Log viewer with filtering
- IP blocklist management
- User authentication UI

**Technology Stack**:
- React 18 + TypeScript
- Tailwind CSS
- Vite
- React Router
- Recharts
- Axios

### 3. API Backend (Go)

**Location**: `api/`

**Responsibilities**:
- RESTful API
- JWT authentication
- Database operations
- WebSocket server for real-time updates
- User management

**Technology Stack**:
- Gin framework
- GORM
- JWT (golang-jwt)
- SQLite/PostgreSQL

### 4. Database

**Models**:
- **User**: Dashboard users with roles
- **Rule**: Custom WAF detection rules
- **Log**: Security event logs
- **BlockedIP**: IP blocklist with expiration

## Data Flow

### Request Processing
```
1. HTTP Request → Caddy
2. WAF Middleware inspects request
3. If threat detected:
   a. Log to JSON file
   b. If block_mode: return 403
   c. Send to SIEM (future)
4. Forward to application
```

### Dashboard Interaction
```
1. User logs in → API validates JWT
2. Dashboard requests data → API queries DB
3. Real-time updates → WebSocket connection
4. User creates rule → API saves to DB → WAF reloads
```

## Security Architecture

### Zero Trust Principles

1. **Identity-based authentication**: JWT tokens required
2. **Least privilege**: Role-based access control (user/admin)
3. **Encryption**: TLS 1.3 everywhere
4. **No exposed ports**: Tailscale Funnel for WAN access

### Defense in Depth
```
Layer 1: Network (Tailscale tunnel)
Layer 2: Firewall (OPNsense DMZ)
Layer 3: WAF (Attack detection)
Layer 4: Application (Input validation)
Layer 5: Database (Parameterized queries)
```

## Performance Optimization

### TLS Tuning
- TLS 1.3 only
- Modern ciphers (AES-GCM, ChaCha20-Poly1305)
- Session resumption
- OCSP stapling

### Compression
- Gzip/Zstd for text content
- Brotli for static assets

### Caching
- Static file caching
- ETags
- Cache-Control headers

## Deployment

### Development
```bash
# Terminal 1: WAF
cd waf && xcaddy run

# Terminal 2: API
cd api && go run cmd/api-server/main.go

# Terminal 3: Dashboard
cd dashboard && npm run dev
```

### Production
```bash
docker-compose up -d
```

## Monitoring

### Logs
- WAF logs: `/var/log/caddy/waf.log` (JSON)
- Access logs: `/var/log/caddy/access.log` (JSON)
- API logs: stdout (structured)

### Metrics
- Requests per second
- Threats detected
- Blocked requests
- Response times

## SIEM Integration

### Log Format
```json
{
  "timestamp": "2025-10-23T20:00:00Z",
  "threat_type": "XSS",
  "severity": "HIGH",
  "client_ip": "192.168.1.100",
  "method": "GET",
  "url": "/search?q=<script>alert(1)</script>",
  "payload": "<script>alert(1)</script>"
}
```

### Forwarding Options
- Filebeat → Elasticsearch
- Fluent Bit → Graylog
- Custom webhook → SIEM API

## Future Enhancements

1. Machine learning-based detection
2. Geographic IP blocking
3. Rate limiting per IP
4. Behavioral analysis
5. Threat intelligence integration
6. Advanced reporting