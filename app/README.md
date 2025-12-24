# Demo Applications for WAF Testing

This directory contains demonstration applications designed to test the WAF's protection capabilities in realistic scenarios. These applications simulate vulnerable web applications that can be used to verify WAF detection rules and blocking mechanisms.

## 📁 Applications

### 1. Finance Application (`finance/`)
A banking and portfolio management demo application that simulates a financial services platform.

**Features:**
- Portfolio dashboard with real-time asset values
- Transaction history
- Mock financial data endpoints
- Realistic banking UI

**Use Cases:**
- Test XSS protection in financial forms
- Test SQL injection in transaction queries
- Test authentication bypass attempts
- Validate protection of sensitive financial data

**Port:** `3000`

---

### 2. Industrial IoT Application (`industrial/`)
An Industrial Control System (ICS) / SCADA simulation representing critical infrastructure monitoring.

**Features:**
- PLC (Programmable Logic Controller) status monitoring
- Industrial protocol tracking (Modbus, DNP3, OPC UA, MQTT)
- Sensor readings dashboard
- Real-time SCADA metrics

**Use Cases:**
- Test protection of industrial protocols
- Test command injection in control systems
- Test SSRF attacks targeting internal networks
- Validate critical infrastructure security

**Port:** `3001`

---

## 🚀 Quick Start

### Prerequisites
- Node.js 14+ (both applications use Express.js)
- WAF and API backend running (optional, but recommended for full testing)

### Running Finance Application

```bash
cd finance
node server.js
```

The finance application will be available at `http://localhost:3000`

**Health Check:**
```bash
curl http://localhost:3000/health
```

---

### Running Industrial Application

```bash
cd industrial
node server.js
```

The industrial application will be available at `http://localhost:3001`

**Health Check:**
```bash
curl http://localhost:3001/health
```

---

## 🧪 Testing WAF Protection

### Prerequisites for WAF Testing
1. **WAF** must be running and configured to proxy requests to the demo apps
2. **API Backend** should be running to log detected threats
3. **Dashboard** (optional) for visualizing blocked attacks

### Example Attack Vectors to Test

#### XSS Testing
```bash
# Test reflected XSS
curl 'http://localhost:3000/api/portfolio?user=<script>alert(1)</script>'

# Test stored XSS
curl -X POST 'http://localhost:3000/api/transactions' \
  -H "Content-Type: application/json" \
  -d '{"description":"<img src=x onerror=alert(1)>"}'
```

#### SQL Injection Testing
```bash
# Test SQLi in query parameter
curl 'http://localhost:3000/api/portfolio?id=1%20OR%201=1'

# Test Union-based SQLi
curl 'http://localhost:3000/api/transactions?id=1%20UNION%20SELECT%20null'
```

#### Command Injection Testing
```bash
# Test command injection
curl 'http://localhost:3001/api/plc-status?id=PLC-001;ls%20-la'

# Test with backticks
curl 'http://localhost:3001/api/sensors?sensor=`whoami`'
```

#### SSRF Testing
```bash
# Test SSRF to internal network
curl -X POST 'http://localhost:3001/api/protocols' \
  -H "Content-Type: application/json" \
  -d '{"target":"http://169.254.169.254/latest/meta-data/"}'
```

#### Path Traversal Testing
```bash
# Test LFI
curl 'http://localhost:3000/api/transactions?file=../../etc/passwd'

# Test directory traversal
curl 'http://localhost:3001/api/sensors?config=../../../config.json'
```

---

## 🔍 Expected Behavior with WAF

When the WAF is properly configured and running:

1. **Attack Requests** should be blocked with `403 Forbidden` responses
2. **Threat Logs** should appear in the API backend database
3. **Dashboard Alerts** should show real-time threat detection
4. **IP Blocking** may be triggered after multiple attack attempts
5. **SIEM Integration** should log structured security events

**Legitimate Requests:**
```bash
# These should work normally
curl http://localhost:3000/api/portfolio
curl http://localhost:3001/api/plc-status
```

---

## 📊 Application Endpoints

### Finance Application (`http://localhost:3000`)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main portfolio dashboard |
| `/health` | GET | Health check endpoint |
| `/api/portfolio` | GET | Get portfolio data |
| `/api/transactions` | GET | Get transaction history |

### Industrial Application (`http://localhost:3001`)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main SCADA dashboard |
| `/health` | GET | Health check endpoint |
| `/api/plc-status` | GET | Get PLC unit statuses |
| `/api/protocols` | GET | Get active protocol information |
| `/api/sensors` | GET | Get sensor readings |

---

## 🛡️ WAF Integration

### Caddyfile Configuration Example

To proxy these applications through the WAF:

```caddy
# Finance Application (Protected by WAF)
:443 {
    # Layer 1: Coraza WAF
    coraza_waf {
        directives `Include /etc/caddy/waf/coraza.conf`
    }

    # Layer 2: Custom WAF
    custom_waf {
        log_file /var/log/caddy/waf_finance.log
        block_mode true
        api_endpoint http://localhost:8081/api
    }

    reverse_proxy localhost:3000
}

# Industrial Application (Protected by WAF)
:8443 {
    coraza_waf {
        directives `Include /etc/caddy/waf/coraza.conf`
    }

    custom_waf {
        log_file /var/log/caddy/waf_industrial.log
        block_mode true
        api_endpoint http://localhost:8081/api
    }

    reverse_proxy localhost:3001
}
```

---

## 🧩 Architecture

```
┌─────────────────┐
│  Attack Traffic │
└────────┬────────┘
         │
         v
┌─────────────────────────────┐
│   Caddy + Dual WAF          │
│  ┌────────────────────┐     │
│  │ Layer 1: Coraza    │     │
│  └────────┬───────────┘     │
│           │ PASS             │
│           v                  │
│  ┌────────────────────┐     │
│  │ Layer 2: Custom    │     │
│  └────────┬───────────┘     │
└───────────┼──────────────────┘
            │ PASS
            v
┌─────────────────────────────┐
│   Demo Applications         │
│  ┌──────────┐ ┌──────────┐ │
│  │ Finance  │ │Industrial│ │
│  │  :3000   │ │  :3001   │ │
│  └──────────┘ └──────────┘ │
└─────────────────────────────┘
```

---

## 🚨 Security Notes

**⚠️ IMPORTANT: These applications are intentionally vulnerable for testing purposes.**

- **DO NOT deploy in production environments**
- **DO NOT expose to the public internet**
- Use only in isolated testing/development environments
- Always run behind the WAF for proper protection
- Intended for security research and WAF validation only

---

## 📝 Development

### Adding Custom Test Endpoints

You can extend these applications to test additional attack vectors:

**Example - Adding a new vulnerable endpoint:**

```javascript
// In finance/server.js or industrial/server.js
app.get('/api/search', (req, res) => {
    const query = req.query.q; // Intentionally vulnerable to XSS
    res.send(`<h1>Search results for: ${query}</h1>`);
});
```

Then test with:
```bash
curl 'http://localhost:3000/api/search?q=<script>alert(1)</script>'
```

---

## 🔗 Related Documentation

- [Architecture Guide](../docs/architecture.md)
- [Installation Guide](../docs/installation.md)
- [Configuration Guide](../docs/configuration.md)
- [Deployment Guide](../DEPLOYMENT.md)
- [WAF Documentation](../waf/README.md)
- [API Documentation](../api/README.md)
- [Dashboard Documentation](../dashboard/README.md)
- [Main Project README](../README.md)

---

## 📦 Dependencies

Both applications use minimal dependencies:
- **express** - Web framework
- **path** - Path utilities (Node.js built-in)

No `package.json` required - applications use Node.js built-in modules and Express only.

---

## 🤝 Contributing

To add new test applications:

1. Create a new directory (e.g., `app/ecommerce/`)
2. Add `server.js` with vulnerable endpoints
3. Add `index.html` with UI
4. Update this README with the new application details
5. Document the attack vectors it helps test

---

## 📄 License

Part of the WAF-SIEM Advanced Detection project. See main [LICENSE](../LICENSE) file.
