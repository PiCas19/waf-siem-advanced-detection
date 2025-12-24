# WAF-Enhanced Web Server with SIEM Integration for Advanced Threat Detection
WAF-enhanced Caddy web server that inspects HTTP traffic, blocks common attacks (XSS, SQLi, RFI), and forwards structured security events to a SIEM for real-time monitoring, threat correlation, dashboards, and automated response. Provides scalable protection with modular rules, logging, and threat intelligence.


## 🎯 Project Overview
This project implements a comprehensive Web Application Firewall (WAF) as a Caddy middleware with real-time threat detection, dashboard management, and SIEM integration capabilities.


## ✨ Features

- ✅ **WAF Middleware** - Modular Caddy plugin for request inspection
- ✅ **Multi-Attack Detection**
  - Cross-Site Scripting (XSS)
  - SQL Injection (SQLi)
  - Local File Inclusion (LFI)
  - Remote File Inclusion (RFI)
  - Command Injection
- ✅ **JWT Authentication** - Secure API access with token-based auth
- ✅ **Real-time Dashboard** - React-based UI for monitoring and management
- ✅ **Custom Rules Engine** - Add and manage detection rules via dashboard
- ✅ **SIEM Integration** - Structured JSON logging for centralized monitoring
- ✅ **Performance Optimization** - TLS tuning, compression, and caching
- ✅ **Dynamic IP Blocklist** - Automatic blocking of malicious clients

## 📁 Project Structure
```
waf-siem-advanced-detection/
├── waf/              # WAF core module (Go)
├── dashboard/        # React dashboard (TypeScript)
├── api/              # Backend API (Go + JWT)
└── docs/             # Documentation
```

## 🚀 Quick Start

### Prerequisites

- Go 1.21+
- Node.js 18+
- xcaddy
- Docker (optional)

### Build WAF
```bash
cd waf
xcaddy build --with github.com/PiCas19/waf-siem-advanced-detection/waf
```

### Run Dashboard
```bash
cd dashboard
npm install
npm run dev
```

### Run API
```bash
cd api
go run cmd/api-server/main.go
```

## 📖 Documentation

- [Architecture](docs/architecture.md)
- [Installation Guide](docs/installation.md)
- [API Reference](docs/api-reference.md)
- [Configuration](docs/configuration.md)

## 🔒 Security

This project implements Zero Trust Network Access (ZTNA) principles:
- Identity-based authentication
- Least privilege access
- Continuous verification
- Encrypted communication (Tailscale integration)


## 📊 Technology Stack

- **WAF Core**: Go 1.21
- **Web Server**: Caddy 2.x
- **Dashboard**: React 18 + TypeScript + Tailwind CSS
- **API**: Go + Gin framework
- **Auth**: JWT (golang-jwt)
- **Database**: SQLite/PostgreSQL
- **Deployment**: Docker, Kubernetes


## 🧪 Testing
```bash
# Run WAF tests
cd waf && go test ./...

# Run integration tests
./scripts/test.sh
```
## 📝 License

See [LICENSE](LICENSE) file for details.

## 👥 Author

Project developed as part of MSE (Master of Science in Engineering) coursework.

## 🤝 Contributing

This is an academic project. Contributions are welcome for educational purposes.

