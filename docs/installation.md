# Installation Guide

Complete installation guide for WAF-SIEM Advanced Detection system.

## Prerequisites

### Required Software

- **Go 1.24+** - [Download](https://golang.org/dl/)
- **Node.js 20+** - [Download](https://nodejs.org/)
- **xcaddy** - For building Caddy with custom modules
- **Git** - For cloning the repository

### Install xcaddy

```bash
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
```

### System Requirements

- **RAM**: Minimum 2GB (4GB+ recommended for production)
- **Disk**: 10GB+ free space
- **OS**: Linux, macOS, or Windows
- **Network**: Internet connection for dependencies

---

## Quick Start (Development)

### 1. Clone Repository

```bash
git clone https://github.com/PiCas19/waf-siem-advanced-detection.git
cd waf-siem-advanced-detection
```

### 2. Build WAF

```bash
cd waf
chmod +x scripts/build-caddy-coraza.sh
./scripts/build-caddy-coraza.sh
```

This creates `caddy` binary with all WAF modules.

### 3. Setup API Backend

```bash
cd ../api

# Create .env file
cat > .env << 'EOF'
PORT=8081
SERVER_HOST=0.0.0.0
JWT_SECRET=$(openssl rand -base64 64 | tr -d '\n')
DB_PATH=./waf.db
LOG_LEVEL=info
EOF

# Download dependencies
go mod download

# Run API server
go run cmd/api-server/main.go
```

### 4. Setup Dashboard

```bash
cd ../dashboard

# Install dependencies
npm install

# Create .env file
cat > .env << 'EOF'
VITE_API_URL=http://localhost:8081
VITE_WS_URL=ws://localhost:8081/ws
EOF

# Run development server
npm run dev
```

### 5. Start WAF

```bash
cd ../waf
./caddy run --config configs/Caddyfile
```

### 6. Access Dashboard

Open browser: [http://localhost:3000](http://localhost:3000)

**Default Credentials**:
- Email: `admin@example.com`
- Password: Check API startup logs for generated password

---

## Production Installation

### Option 1: Automated Deployment Script (Recommended)

```bash
cd waf
chmod +x scripts/deploy-coraza.sh
./scripts/deploy-coraza.sh
```

This script:
- Builds Caddy with all modules
- Downloads OWASP Core Rule Set
- Creates systemd services
- Sets up log rotation
- Configures firewall rules

### Option 2: Manual Installation

#### Step 1: Build Caddy WAF

```bash
cd waf
xcaddy build v2.10.2 \
    --with github.com/corazawaf/coraza-caddy/v2@latest \
    --with github.com/PiCas19/waf-siem-advanced-detection/waf=./ \
    --with github.com/tailscale/caddy-tailscale

# Install binary
sudo cp caddy /usr/local/bin/
sudo chmod +x /usr/local/bin/caddy
```

#### Step 2: Install OWASP Core Rule Set

```bash
sudo mkdir -p /etc/caddy/waf
cd /etc/caddy/waf

# Download CRS v4.7.0
sudo wget https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.7.0.tar.gz
sudo tar -xzf v4.7.0.tar.gz
sudo mv coreruleset-4.7.0 coreruleset

# Copy Coraza configuration
sudo cp ~/waf-siem-advanced-detection/waf/configs/coraza.conf /etc/caddy/waf/
sudo cp ~/waf-siem-advanced-detection/waf/configs/Caddyfile /etc/caddy/
```

#### Step 3: Create WAF Service

```bash
sudo nano /etc/systemd/system/caddy.service
```

```ini
[Unit]
Description=Caddy WAF Web Server
Documentation=https://caddyserver.com/docs/
After=network.target network-online.target
Requires=network-online.target

[Service]
Type=notify
User=caddy
Group=caddy
ExecStart=/usr/local/bin/caddy run --config /etc/caddy/Caddyfile
ExecReload=/usr/local/bin/caddy reload --config /etc/caddy/Caddyfile --force
TimeoutStopSec=5s
LimitNOFILE=1048576
LimitNPROC=512
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=/var/log/caddy /etc/caddy/waf

[Install]
WantedBy=multi-user.target
```

```bash
# Create caddy user
sudo useradd -r -s /bin/false caddy

# Create log directory
sudo mkdir -p /var/log/caddy
sudo chown caddy:caddy /var/log/caddy

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable caddy
sudo systemctl start caddy
```

#### Step 4: Build and Install API

```bash
cd ~/waf-siem-advanced-detection/api

# Build binary
CGO_ENABLED=0 go build -ldflags="-s -w" -o waf-api cmd/api-server/main.go

# Install
sudo cp waf-api /usr/local/bin/
sudo chmod +x /usr/local/bin/waf-api

# Create directories
sudo mkdir -p /var/lib/waf
sudo mkdir -p /etc/waf

# Create .env configuration
sudo nano /etc/waf/api.env
```

```bash
PORT=8081
SERVER_HOST=0.0.0.0
JWT_SECRET=your-secure-random-secret-change-me
DB_PATH=/var/lib/waf/waf.db
LOG_LEVEL=info
LOG_OUTPUT=/var/log/waf-api/api.log
RATE_LIMIT_ENABLED=true
```

```bash
# Create API service
sudo nano /etc/systemd/system/waf-api.service
```

```ini
[Unit]
Description=WAF API Backend
After=network.target

[Service]
Type=simple
User=waf-api
Group=waf-api
WorkingDirectory=/var/lib/waf
EnvironmentFile=/etc/waf/api.env
ExecStart=/usr/local/bin/waf-api
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

```bash
# Create user and directories
sudo useradd -r -s /bin/false waf-api
sudo mkdir -p /var/log/waf-api
sudo chown -R waf-api:waf-api /var/lib/waf /var/log/waf-api

# Start service
sudo systemctl daemon-reload
sudo systemctl enable waf-api
sudo systemctl start waf-api
```

#### Step 5: Build and Deploy Dashboard

```bash
cd ~/waf-siem-advanced-detection/dashboard

# Create production .env
cat > .env << 'EOF'
VITE_API_URL=https://your-domain.com/api
VITE_WS_URL=wss://your-domain.com/ws
EOF

# Build
npm run build

# Deploy to web server
sudo mkdir -p /var/www/html/dashboard
sudo cp -r dist/* /var/www/html/dashboard/
sudo chown -R caddy:caddy /var/www/html/dashboard
```

---

## Docker Installation

### Using Docker Compose

```bash
cd deployment/docker
docker-compose up -d
```

### Manual Docker Build

```bash
# Build API
docker build -t waf-api -f api/Dockerfile .

# Build Dashboard
docker build -t waf-dashboard -f dashboard/Dockerfile .

# Build WAF
docker build -t caddy-waf -f waf/Dockerfile .

# Run containers
docker run -d -p 8081:8081 --name api waf-api
docker run -d -p 3000:80 --name dashboard waf-dashboard
docker run -d -p 443:443 --name waf caddy-waf
```

---

## Configuration

### 1. Configure Caddyfile

Edit `/etc/caddy/Caddyfile`:

```caddy
{
    email admin@your-domain.com
    auto_https on
}

:443 {
    tls /etc/caddy/certs/cert.pem /etc/caddy/certs/privkey.pem

    # Layer 1: Coraza WAF
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
    }

    # Dashboard
    handle /dashboard* {
        root * /var/www/html/dashboard
        try_files {path} /index.html
        file_server
    }

    # API Proxy
    reverse_proxy /api/* localhost:8081

    # WebSocket
    reverse_proxy /ws localhost:8081

    # Your application
    reverse_proxy backend:3000
}
```

### 2. Configure API Backend

Edit `/etc/waf/api.env` and set secure values.

### 3. Setup SSL Certificates

#### Option A: Let's Encrypt (Automatic)

Caddy handles this automatically if you use a domain name.

#### Option B: Custom Certificates

```bash
sudo mkdir -p /etc/caddy/certs
# Copy your cert.pem and privkey.pem
sudo cp cert.pem /etc/caddy/certs/
sudo cp privkey.pem /etc/caddy/certs/
sudo chown caddy:caddy /etc/caddy/certs/*
```

---

## Verification

### Test WAF Protection

```bash
# Should be blocked (XSS)
curl -k 'https://your-domain/test?q=<script>alert(1)</script>'

# Should pass
curl -k 'https://your-domain/test?q=hello'
```

### Check Logs

```bash
# WAF logs
sudo tail -f /var/log/caddy/waf.log | jq .

# API logs
sudo tail -f /var/log/waf-api/api.log

# Caddy logs
sudo journalctl -u caddy -f
```

### Check Services

```bash
sudo systemctl status caddy
sudo systemctl status waf-api
```

---

## Post-Installation

### 1. Create Admin User

Access dashboard and login with default credentials, then:
- Change admin password
- Enable 2FA
- Create additional users

### 2. Configure Firewall

```bash
# UFW example
sudo ufw allow 443/tcp
sudo ufw allow 80/tcp
sudo ufw enable
```

### 3. Setup Log Rotation

```bash
sudo nano /etc/logrotate.d/waf
```

```
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

### 4. Setup Backups

```bash
# Create backup script
sudo nano /usr/local/bin/backup-waf.sh
```

```bash
#!/bin/bash
BACKUP_DIR="/var/backups/waf"
DATE=$(date +%Y%m%d-%H%M%S)

mkdir -p $BACKUP_DIR

# Backup database
sqlite3 /var/lib/waf/waf.db ".backup $BACKUP_DIR/waf-$DATE.db"

# Backup configurations
tar -czf $BACKUP_DIR/config-$DATE.tar.gz /etc/caddy /etc/waf

# Keep last 30 days
find $BACKUP_DIR -type f -mtime +30 -delete

echo "Backup completed: $DATE"
```

```bash
sudo chmod +x /usr/local/bin/backup-waf.sh

# Add to crontab (daily at 2 AM)
sudo crontab -e
# Add: 0 2 * * * /usr/local/bin/backup-waf.sh
```

---

## Troubleshooting

### WAF Not Blocking

1. Check Caddy modules loaded:
   ```bash
   caddy list-modules | grep -E '(coraza|custom_waf)'
   ```

2. Verify Coraza config:
   ```bash
   ls -la /etc/caddy/waf/coreruleset/rules/
   ```

3. Check Caddyfile syntax:
   ```bash
   caddy validate --config /etc/caddy/Caddyfile
   ```

### API Not Starting

1. Check database permissions:
   ```bash
   ls -la /var/lib/waf/
   ```

2. Verify environment variables:
   ```bash
   sudo systemctl status waf-api
   sudo journalctl -u waf-api -n 50
   ```

3. Test database connection:
   ```bash
   sqlite3 /var/lib/waf/waf.db ".tables"
   ```

### Dashboard Not Loading

1. Check API is running:
   ```bash
   curl http://localhost:8081/api/stats
   ```

2. Verify CORS settings in API `.env`

3. Check browser console for errors

### Permission Errors

```bash
# Fix Caddy permissions
sudo chown -R caddy:caddy /var/log/caddy /etc/caddy

# Fix API permissions
sudo chown -R waf-api:waf-api /var/lib/waf /var/log/waf-api
```

---

## Updating

### Update WAF

```bash
cd ~/waf-siem-advanced-detection
git pull

cd waf
./scripts/build-caddy-coraza.sh
sudo systemctl restart caddy
```

### Update API

```bash
cd ~/waf-siem-advanced-detection/api
git pull
go build -o waf-api cmd/api-server/main.go
sudo cp waf-api /usr/local/bin/
sudo systemctl restart waf-api
```

### Update Dashboard

```bash
cd ~/waf-siem-advanced-detection/dashboard
git pull
npm install
npm run build
sudo cp -r dist/* /var/www/html/dashboard/
```

---

## Additional Resources

- [Architecture Documentation](architecture.md)
- [Configuration Guide](configuration.md)
- [API Reference](api-reference.md)
- [OWASP CRS Documentation](https://coreruleset.org/)
- [Caddy Documentation](https://caddyserver.com/docs/)

---

## Support

For issues and questions:
- GitHub Issues: [https://github.com/PiCas19/waf-siem-advanced-detection/issues](https://github.com/PiCas19/waf-siem-advanced-detection/issues)
- Documentation: [docs/](.)
