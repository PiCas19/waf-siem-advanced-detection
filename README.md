# WAF-Enhanced Web Server with SIEM Integration for Advanced Threat Detection

Dual-layer Web Application Firewall (WAF) system built on Caddy that combines OWASP ModSecurity Core Rule Set (Coraza WAF) with custom business logic protection. The system inspects HTTP traffic, blocks common attacks (XSS, SQLi, RFI, RCE, etc.), and provides real-time monitoring through a React-based dashboard with SIEM integration for centralized security management.

## 🎯 Project Overview

This project implements a comprehensive dual-layer Web Application Firewall (WAF) system:

- **Layer 1**: OWASP ModSecurity Core Rule Set via Coraza WAF (200+ automatic protection rules)
- **Layer 2**: Custom business logic WAF with dynamic rules, IP intelligence, and flexible blocking actions

The system includes a complete management infrastructure with RESTful API backend, real-time dashboard, JWT authentication, and demo applications for testing WAF capabilities.


## ✨ Features

### Layer 1: OWASP Protection (Coraza WAF)
- ✅ **200+ OWASP Rules** - ModSecurity Core Rule Set v4.0
- ✅ **OWASP Top 10 Coverage** - XSS, SQLi, RCE, Path Traversal, Scanner Detection
- ✅ **Protocol Validation** - HTTP protocol anomaly detection
- ✅ **Data Leakage Prevention** - Sensitive data exposure protection
- ✅ **Evasion Techniques Detection** - Advanced attack pattern recognition

### Layer 2: Custom Business Logic Protection
- ✅ **100+ Built-in Detectors** - XSS, SQLi, SSRF, SSTI, XXE, NoSQL, LDAP Injection, Prototype Pollution
- ✅ **Dynamic Custom Rules** - Database-managed regex-based rules via dashboard
- ✅ **IP Intelligence** - Tailscale network detection, DMZ detection, HMAC validation
- ✅ **Flexible Blocking Actions** - Block (403), Drop connection, Redirect (302), CAPTCHA Challenge
- ✅ **IP Blocklist/Whitelist** - Dynamic IP management with priority system
- ✅ **Manual Block Rules** - High-priority rules for specific threat response

### Management & Monitoring
- ✅ **RESTful API Backend** - Go-based API with JWT authentication
- ✅ **Real-time Dashboard** - React + TypeScript UI with live threat monitoring
- ✅ **WebSocket Integration** - Real-time alerts and notifications
- ✅ **SIEM Integration** - Structured JSON logging for centralized monitoring
- ✅ **Statistics & Analytics** - Attack trends, threat correlation, and reporting
- ✅ **User Management** - Multi-user support with role-based access

### Testing & Development
- ✅ **Demo Applications** - Finance and Industrial IoT test applications
- ✅ **Comprehensive Testing** - Unit tests, integration tests, end-to-end tests
- ✅ **Performance Optimization** - TLS tuning, compression, and caching

## 📁 Project Structure
```
waf-siem-advanced-detection/
├── waf/              # Dual-layer WAF module (Go + Caddy)
│   ├── internal/     # Core WAF logic (detectors, rules, blocklist, IP intelligence)
│   ├── pkg/waf/      # Caddy middleware integration
│   ├── configs/      # Caddyfile and Coraza configuration
│   └── scripts/      # Build and deployment scripts
├── api/              # Backend RESTful API (Go + Gin + JWT)
│   ├── cmd/          # API server entry point
│   ├── internal/     # API business logic, handlers, middleware
│   └── tests/        # API tests
├── dashboard/        # React-based management UI (TypeScript + Vite)
│   ├── src/          # React components, services, hooks
│   ├── cypress/      # E2E tests
│   └── public/       # Static assets
├── app/              # Demo applications for WAF testing
│   ├── finance/      # Banking/Finance demo app (Node.js)
│   └── industrial/   # Industrial IoT/SCADA demo app (Node.js)
└── docs/             # Project documentation
```

## 🚀 Quick Start

### Prerequisites

- Go 1.21+
- Node.js 18+
- xcaddy (for building Caddy with WAF modules)
- Docker (optional, for containerized deployment)

### 1. Build and Run WAF
```bash
cd waf

# Build Caddy with Coraza and Custom WAF modules
chmod +x scripts/build-caddy-coraza.sh
scripts/build-caddy-coraza.sh

# Run Caddy
./caddy run --config configs/Caddyfile
```

### 2. Run API Backend
```bash
cd api

# Install dependencies
go mod download

# Run API server
go run cmd/api-server/main.go
# API available at http://localhost:8081
```

### 3. Run Dashboard
```bash
cd dashboard

# Install dependencies
npm install

# Run development server
npm run dev
# Dashboard available at http://localhost:3000
```

### 4. Run Demo Applications (Optional)
```bash
# Finance application
cd app/finance
node server.js
# Available at http://localhost:3000

# Industrial IoT application
cd app/industrial
node server.js
# Available at http://localhost:3001
```

## 📖 Documentation

- [Architecture](docs/architecture.md) - System architecture and design
- [Installation Guide](docs/installation.md) - Setup and installation
- [API Reference](docs/api-reference.md) - API endpoints documentation
- [Configuration](docs/configuration.md) - Configuration options
- [Deployment Guide](DEPLOYMENT.md) - Production deployment

## 🔒 Security

This project implements Zero Trust Network Access (ZTNA) principles:
- Identity-based authentication
- Least privilege access
- Continuous verification
- Encrypted communication (Tailscale integration)


## 📊 Technology Stack

### WAF Layer
- **Caddy** 2.x - High-performance web server
- **Coraza WAF** - OWASP ModSecurity Core Rule Set implementation
- **Go** 1.21+ - Custom WAF logic and middleware

### Backend API
- **Go** 1.21+ with Gin framework
- **JWT** Authentication (golang-jwt)
- **SQLite** - Default database (PostgreSQL compatible)
- **WebSocket** - Real-time alerts

### Frontend Dashboard
- **React** 18 with TypeScript
- **Vite** - Build tool and dev server
- **Tailwind CSS** - Styling framework
- **Recharts** - Data visualization
- **Axios** - HTTP client
- **Cypress** - E2E testing

### Demo Applications
- **Node.js** + Express - Finance and Industrial IoT apps

### Deployment & DevOps
- **Docker** - Containerization
- **GitHub Actions** - CI/CD pipelines
- **Systemd** - Service management
- **Filebeat** - Log forwarding to SIEM

## 📝 License

See [LICENSE](LICENSE) file for details.

## 👥 Author

Project developed by Pierpaolo Casati – contact: pierpaolo.casati@bluewin.ch

## 🤝 Contributing

This is an academic project. Contributions are welcome for educational purposes.

