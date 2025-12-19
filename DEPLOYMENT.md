# WAF SIEM Advanced Detection - Deployment Package

This package contains everything needed to deploy the WAF-SIEM Advanced Detection system.

## Package Contents

- `api/bin/` - API server binaries for multiple platforms
- `waf/bin/` - WAF binaries (Caddy + Coraza Forwarder) for multiple platforms
- `dashboard/` - Pre-built dashboard (static files)
- `waf/configs/` - WAF configuration files
- `waf/scripts/` - Deployment and management scripts
- `docs/` - Documentation
- `app/` - Sample applications

## Quick Start

### 1. API Server

**Linux:**
```bash
cd api/bin
chmod +x api-server-linux-amd64
./api-server-linux-amd64
```

**macOS (Intel):**
```bash
cd api/bin
chmod +x api-server-darwin-amd64
./api-server-darwin-amd64
```

**macOS (Apple Silicon):**
```bash
cd api/bin
chmod +x api-server-darwin-arm64
./api-server-darwin-arm64
```

**Windows:**
```powershell
cd api\bin
.\api-server-windows-amd64.exe
```

### 2. WAF

**Linux:**
```bash
cd waf/bin
chmod +x caddy-waf-linux-amd64

# Start Caddy WAF
./caddy-waf-linux-amd64 run --config ../configs/Caddyfile
```

**macOS:**
```bash
cd waf/bin
chmod +x caddy-waf-darwin-arm64  # or darwin-amd64 for Intel

# Start Caddy WAF
./caddy-waf-darwin-arm64 run --config ../configs/Caddyfile
```

**Windows:**
```powershell
cd waf\bin
.\caddy-waf-windows-amd64.exe run --config ..\configs\Caddyfile
```

### 3. Dashboard

Serve the `dashboard/` directory with any web server:

**Using Python:**
```bash
cd dashboard
python3 -m http.server 3000
```

**Using Node.js:**
```bash
cd dashboard
npx serve -s . -p 3000
```

**Using Nginx:**
```bash
sudo cp -r dashboard/* /var/www/html/
```

**Using Caddy (included):**
The dashboard is automatically served when you run the Caddy WAF if configured in the Caddyfile.

## Configuration

### 1. API Configuration

Create `.env` file in the API directory or set environment variables:

```bash
# Minimum required configuration
export PORT=8081
export JWT_SECRET="your-secure-random-secret-change-me-minimum-64-chars"
export DB_PATH="./waf.db"
export LOG_LEVEL="info"
```

**Security:** Generate a strong JWT secret:
```bash
openssl rand -base64 64
```

### 2. WAF Configuration

Edit `waf/configs/Caddyfile` to configure:
- Server ports and domains
- WAF protection levels
- Reverse proxy targets
- TLS certificates

Example minimal Caddyfile:
```caddy
{
    order custom_waf first
    order coraza_waf before reverse_proxy
}

:443 {
    # Layer 1: Coraza WAF (OWASP)
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
    }

    # Your application
    reverse_proxy backend:3000
}
```

### 3. Dashboard Configuration

The dashboard connects to the API. If the API is not on `http://localhost:8081`, update the API URL:

Create `dashboard/.env.local`:
```bash
VITE_API_URL=http://your-api-server:8081
VITE_WS_URL=ws://your-api-server:8081/ws
```

Then rebuild the dashboard or serve it through a proxy that handles the API routing.

## Platform Selection

Choose the correct binary for your platform:

| Platform | API Binary | WAF Binary |
|----------|------------|------------|
| Linux x64 | `api-server-linux-amd64` | `caddy-waf-linux-amd64` |
| macOS Intel | `api-server-darwin-amd64` | `caddy-waf-darwin-amd64` |
| macOS Apple Silicon | `api-server-darwin-arm64` | `caddy-waf-darwin-arm64` |
| Windows x64 | `api-server-windows-amd64.exe` | `caddy-waf-windows-amd64.exe` |

## Production Deployment

### Using Systemd (Linux)

#### API Service

Create `/etc/systemd/system/waf-api.service`:

```ini
[Unit]
Description=WAF API Backend
After=network.target

[Service]
Type=simple
User=waf-api
WorkingDirectory=/opt/waf-siem/api
Environment="PORT=8081"
Environment="JWT_SECRET=your-secret-here"
Environment="DB_PATH=/var/lib/waf/waf.db"
ExecStart=/opt/waf-siem/api/bin/api-server-linux-amd64
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable waf-api
sudo systemctl start waf-api
```

#### WAF Service

Create `/etc/systemd/system/caddy-waf.service`:

```ini
[Unit]
Description=Caddy WAF Web Server
After=network-online.target
Requires=network-online.target

[Service]
Type=notify
User=caddy
ExecStart=/opt/waf-siem/waf/bin/caddy-waf-linux-amd64 run --config /opt/waf-siem/waf/configs/Caddyfile
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable caddy-waf
sudo systemctl start caddy-waf
```

### Using Docker

Create `docker-compose.yml`:

```yaml
version: '3.8'

services:
  api:
    image: waf-api:latest
    build:
      context: ./api
    ports:
      - "8081:8081"
    environment:
      - JWT_SECRET=your-secret-here
      - DB_PATH=/data/waf.db
    volumes:
      - waf-data:/data

  waf:
    image: caddy-waf:latest
    build:
      context: ./waf
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./waf/configs:/etc/caddy

  dashboard:
    image: nginx:alpine
    ports:
      - "3000:80"
    volumes:
      - ./dashboard:/usr/share/nginx/html

volumes:
  waf-data:
```

```bash
docker-compose up -d
```

## Verification

### 1. Check API

```bash
curl http://localhost:8081/api/stats
```

Expected: JSON response with statistics (or 401 if auth required).

### 2. Test WAF Protection

```bash
# Test XSS blocking
curl 'http://localhost/test?q=<script>alert(1)</script>'
```

Expected: 403 Forbidden

```bash
# Test legitimate request
curl 'http://localhost/test?q=hello'
```

Expected: 200 OK (proxied to backend)

### 3. Access Dashboard

Open browser: [http://localhost:3000](http://localhost:3000)

Default credentials:
- Email: `admin@example.com`
- Password: Check API startup logs or create new admin user

## Monitoring

### Logs

**WAF Logs:**
```bash
tail -f /var/log/caddy/waf.log | jq .
```

**API Logs:**
```bash
journalctl -u waf-api -f
```

**Caddy Logs:**
```bash
journalctl -u caddy-waf -f
```

### Metrics

Access the dashboard to view:
- Total requests processed
- Threats detected and blocked
- Top attacked endpoints
- Geographic threat distribution
- Real-time threat alerts

## Troubleshooting

### API Won't Start

1. Check JWT_SECRET is set:
   ```bash
   echo $JWT_SECRET
   ```

2. Verify database permissions:
   ```bash
   ls -la /var/lib/waf/
   ```

3. Check logs:
   ```bash
   journalctl -u waf-api -n 50
   ```

### WAF Not Blocking

1. Verify Coraza rules are present:
   ```bash
   ls /etc/caddy/waf/coreruleset/rules/
   ```

2. Check Caddyfile syntax:
   ```bash
   ./caddy-waf-linux-amd64 validate --config configs/Caddyfile
   ```

3. Ensure `block_mode true` is set in Caddyfile

### Dashboard Shows No Data

1. Check API connection:
   ```bash
   curl http://localhost:8081/api/stats
   ```

2. Verify CORS settings in API configuration

3. Check browser console for errors (F12)

## Backup and Restore

### Backup

```bash
# Backup database
sqlite3 /var/lib/waf/waf.db ".backup /backup/waf-$(date +%Y%m%d).db"

# Backup configurations
tar -czf /backup/waf-configs-$(date +%Y%m%d).tar.gz \
    waf/configs \
    api/.env
```

### Restore

```bash
# Restore database
sqlite3 /var/lib/waf/waf.db < /backup/waf-20251219.db

# Restore configurations
tar -xzf /backup/waf-configs-20251219.tar.gz
```

## Security Checklist

Before going to production:

- [ ] Change JWT_SECRET to a strong random value
- [ ] Enable HTTPS with valid SSL certificates
- [ ] Set `block_mode true` in WAF configuration
- [ ] Configure firewall to allow only necessary ports
- [ ] Set up log rotation
- [ ] Enable 2FA for admin accounts
- [ ] Review and customize WAF rules
- [ ] Set strong database file permissions (chmod 600)
- [ ] Configure automated backups
- [ ] Test disaster recovery procedures

## Upgrading

### From GitHub Release

1. Download new release package
2. Stop services:
   ```bash
   sudo systemctl stop waf-api caddy-waf
   ```
3. Backup current installation
4. Replace binaries with new versions
5. Start services:
   ```bash
   sudo systemctl start waf-api caddy-waf
   ```

### From Source

Follow the build instructions in [docs/installation.md](docs/installation.md)

## Support and Documentation

- **Full Documentation**: See `docs/` directory
  - [Architecture](docs/architecture.md)
  - [Installation Guide](docs/installation.md)
  - [Configuration](docs/configuration.md)
  - [API Reference](docs/api-reference.md)

- **GitHub Repository**: [https://github.com/PiCas19/waf-siem-advanced-detection](https://github.com/PiCas19/waf-siem-advanced-detection)
- **Issues**: [https://github.com/PiCas19/waf-siem-advanced-detection/issues](https://github.com/PiCas19/waf-siem-advanced-detection/issues)

## License

See LICENSE file in the package root.

---

**Note:** This is a deployment package for production use. For development and customization, clone the full repository from GitHub.
