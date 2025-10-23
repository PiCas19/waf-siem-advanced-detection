# Installation Guide

## Prerequisites

- **Go 1.21+**
- **Node.js 18+**
- **xcaddy** (for building Caddy with custom modules)
- **Git**
- **Make** (optional)

## Quick Start

### 1. Clone Repository
```bash
git clone https://github.com/yourusername/waf-siem-advanced-detection.git
cd waf-siem-advanced-detection
```

### 2. Build WAF Module
```bash
cd waf
xcaddy build --with github.com/yourusername/waf-siem-advanced-detection/waf
```

This creates a `caddy` binary with the WAF module built-in.

### 3. Install Dashboard Dependencies
```bash
cd ../dashboard
npm install
```

### 4. Run API Backend
```bash
cd ../api
go run cmd/api-server/main.go
```

### 5. Run Dashboard
```bash
cd ../dashboard
npm run dev
```

## Detailed Installation

### Building WAF from Source
```bash
cd waf

# Download dependencies
go mod download

# Build with xcaddy
xcaddy build \
  --with github.com/yourusername/waf-siem-advanced-detection/waf \
  --output ./caddy

# Verify
./caddy version
```

### Configuring Caddy

Create `Caddyfile`:
```caddy
{
    order waf before file_server
}

:8080 {
    waf {
        rules /etc/caddy/waf-rules.yaml
        log_file /var/log/caddy/waf.log
        block_mode true
    }
    
    encode gzip zstd
    
    root * /var/www/html
    file_server
    
    reverse_proxy /api/* localhost:8081
}
```

### Running Caddy
```bash
# Validate configuration
./caddy validate --config Caddyfile

# Run in foreground (for testing)
./caddy run --config Caddyfile

# Run as systemd service (production)
sudo systemctl enable caddy
sudo systemctl start caddy
```

## Production Deployment

### Using Docker
```bash
cd deployment/docker
docker-compose up -d
```

### Using Kubernetes
```bash
cd deployment/kubernetes
kubectl apply -f .
```

### Manual Installation

#### 1. Install Caddy
```bash
sudo cp waf/caddy /usr/local/bin/
sudo chmod +x /usr/local/bin/caddy
```

#### 2. Create systemd service
```bash
sudo cp deployment/systemd/caddy-waf.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable caddy-waf
sudo systemctl start caddy-waf
```

#### 3. Install API
```bash
cd api
go build -o waf-api cmd/api-server/main.go
sudo cp waf-api /usr/local/bin/
sudo cp deployment/systemd/waf-api.service /etc/systemd/system/
sudo systemctl enable waf-api
sudo systemctl start waf-api
```

#### 4. Build and serve dashboard
```bash
cd dashboard
npm run build

# Serve with Caddy or Nginx
sudo cp -r dist/* /var/www/html/dashboard/
```

## Configuration

### WAF Rules

Edit `waf/configs/rules.yaml`:
```yaml
rules:
  xss:
    enabled: true
    block_mode: true
    severity: high
```

### Environment Variables

Create `.env`:
```bash
# API
DATABASE_URL=waf.db
JWT_SECRET=your-secret-key-change-me
PORT=8081

# Dashboard
VITE_API_URL=http://localhost:8081
VITE_WS_URL=ws://localhost:8081/ws
```

## Verification

### Test WAF
```bash
# Should be blocked
curl "http://localhost:8080/?q=<script>alert(1)</script>"

# Should pass
curl "http://localhost:8080/?q=hello"
```

### Check Logs
```bash
tail -f /var/log/caddy/waf.log
```

### Access Dashboard

Open browser: `http://localhost:3000`

## Troubleshooting

### WAF not blocking

1. Check `block_mode` is set to `true`
2. Verify rules are loaded: `journalctl -u caddy-waf`
3. Check file permissions on rules file

### API not starting

1. Check port 8081 is free: `lsof -i :8081`
2. Verify database permissions
3. Check logs: `journalctl -u waf-api`

### Dashboard blank

1. Check API is running
2. Verify CORS settings
3. Check browser console for errors

## Updating
```bash
git pull
cd waf && xcaddy build
cd ../dashboard && npm install && npm run build
cd ../api && go build
sudo systemctl restart caddy-waf waf-api
```