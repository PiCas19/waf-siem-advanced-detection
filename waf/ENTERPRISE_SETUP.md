# Enterprise-Grade WAF Configuration Guide

Questo documento descrive come configurare il WAF con le capacità **enterprise-grade** per ambienti production con Tailscale, DMZ, reverse proxy, e SIEM integration.

## Architettura Overview

```
┌─────────────────┐
│  Client (VPN)   │  X-Public-IP: 198.51.100.1 (signed HMAC)
└────────┬────────┘
         │
         │ HTTPS + X-Public-IP header (firmato)
         │
    ┌────▼─────────────────────┐
    │   Tailscale Node          │  Trusted Source Policy
    │   100.64.0.1              │
    └────┬─────────────────────┘
         │
         │ X-Forwarded-For: 100.64.0.1
         │
    ┌────▼──────────────────────┐
    │   Nginx Reverse Proxy      │  Trusted Source Policy
    │   10.0.1.5 (DMZ)           │
    └────┬──────────────────────┘
         │
         │ X-Forwarded-For: 100.64.0.1
         │
    ┌────▼──────────────────────┐
    │   WAF (Caddy)              │  Validates all sources
    │   10.0.2.10 (Private)      │  Enforces trusted policies
    └────┬──────────────────────┘
         │
         │
    ┌────▼──────────────────────┐
    │   Application Backend      │
    │   10.0.3.20                │
    └────────────────────────────┘
         │
         │
    ┌────▼──────────────────────────┐
    │   SIEM (Enterprise Logging)    │
    │   Splunk / ELK / Datadog       │
    └────────────────────────────────┘
```

## 1. Configurazione di Base (Caddyfile)

```caddyfile
# Production Caddyfile with Enterprise IP Detection

example.com {
    # WAF Middleware con configurazioni enterprise
    waf {
        # Basic configuration
        log_file /var/log/waf/events.json
        block_mode false
        api_endpoint http://api-backend:3000
        rules_endpoint http://api-backend:3000/waf/rules
        blocklist_endpoint http://api-backend:3000/waf/blocklist
        whitelist_endpoint http://api-backend:3000/waf/whitelist

        # Traditional trusted proxies
        trusted_proxies 10.0.1.5 10.0.1.6 127.0.0.1

        # Enterprise-grade IP Detection
        enable_hmac_signature_validation true
        hmac_shared_secret your-super-secret-key-change-in-production
        trusted_sources_endpoint http://api-backend:3000/waf/sources

        # DMZ Detection
        enable_dmz_detection true
        dmz_networks 10.0.1.0/24 10.0.2.0/24

        # Tailscale Detection
        enable_tailscale_detection true
        tailscale_networks 100.64.0.0/10
    }

    reverse_proxy localhost:8080
}
```

## 2. Setup Trusted Sources via API

### Creazione di una Tailscale Source

```bash
curl -X POST http://api-backend:3000/waf/sources \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production Tailscale Network",
    "type": "tailscale",
    "ip_range": "100.64.0.0/10",
    "description": "All Tailscale nodes in production VPN",
    "is_enabled": true,
    "trusts_x_public_ip": true,
    "trusts_x_forwarded_for": false,
    "require_signature": true,
    "max_requests_per_min": 10000,
    "blocked_after_errors": 5
  }'
```

### Creazione di una Nginx Reverse Proxy Source (DMZ)

```bash
curl -X POST http://api-backend:3000/waf/sources \
  -H "Content-Type: application/json" \
  -d '{
    "name": "DMZ Nginx Proxy",
    "type": "reverse_proxy",
    "ip": "10.0.1.5",
    "ip_range": "10.0.1.0/24",
    "description": "Primary Nginx reverse proxy in DMZ",
    "is_enabled": true,
    "trusts_x_forwarded_for": true,
    "trusts_x_real_ip": true,
    "require_signature": false,
    "location": "AWS us-east-1 DMZ Zone",
    "geolocation_country": "US"
  }'
```

### Creazione di un Load Balancer Source

```bash
curl -X POST http://api-backend:3000/waf/sources \
  -H "Content-Type: application/json" \
  -d '{
    "name": "AWS ALB",
    "type": "load_balancer",
    "ip_range": "10.0.0.0/8",
    "description": "AWS Application Load Balancer range",
    "is_enabled": true,
    "trusts_x_forwarded_for": true,
    "require_signature": false,
    "location": "AWS Multiple AZs",
    "geolocation_country": "US"
  }'
```

## 3. HMAC Signature Generation (Client Side)

### Tailscale Client - Come Firmare X-Public-IP

```go
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

func generateSignedPublicIP(publicIP string, sharedSecret string) (signature string, timestamp string) {
	timestamp = fmt.Sprintf("%d", time.Now().Unix())

	// Payload: IP|timestamp|GET|/api/data
	payload := strings.Join([]string{publicIP, timestamp, "GET", "/api/data"}, "|")

	// HMAC-SHA256
	h := hmac.New(sha256.New, []byte(sharedSecret))
	h.Write([]byte(payload))
	signature = hex.EncodeToString(h.Sum(nil))

	return
}

func main() {
	publicIP := "203.0.113.45"
	sharedSecret := "your-super-secret-key"

	signature, timestamp := generateSignedPublicIP(publicIP, sharedSecret)

	fmt.Printf("Add these headers to your request:\n")
	fmt.Printf("X-Public-IP: %s\n", publicIP)
	fmt.Printf("X-HMAC-Signature: %s\n", signature)
	fmt.Printf("X-Request-Timestamp: %s\n", timestamp)
}
```

## 4. HMAC Key Management

### Creare una HMAC Key per una Sorgente

```bash
TRUSTED_SOURCE_ID=$(curl -s http://api-backend:3000/waf/sources | jq -r '.sources[0].id')

curl -X POST http://api-backend:3000/waf/hmac-keys \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"Tailscale Primary Key\",
    \"secret\": \"your-64-char-random-secret-here-minimum-32-characters\",
    \"trusted_source_id\": \"$TRUSTED_SOURCE_ID\",
    \"rotation_interval\": 90,
    \"is_active\": true
  }"
```

### Ruotare una HMAC Key (Key Rotation)

```bash
HMAC_KEY_ID="your-key-id"

# Deactivate old key and create new one
curl -X POST http://api-backend:3000/waf/hmac-keys/$HMAC_KEY_ID/rotate
```

## 5. Nginx Reverse Proxy Configuration

### Nginx as Trusted Reverse Proxy (DMZ)

```nginx
upstream backend {
    server 10.0.3.20:8080;
}

server {
    listen 80 on_queue=1024;
    server_name _;

    # Nginx as DMZ reverse proxy
    # Client → Nginx (DMZ) → WAF → Backend

    location / {
        proxy_pass http://backend;

        # Forward original client IP from Tailscale
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $server_name;

        # WAF-specific headers
        proxy_set_header X-Forwarded-By "nginx-dmz-01";
        proxy_set_header X-DMZ-Source "true";

        # Connection settings
        proxy_connect_timeout 10s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;

        # Buffering
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
    }

    # Health check endpoint
    location /health {
        return 200 "OK";
    }
}
```

## 6. IP Detection Trust Scoring

Il WAF calcola automaticamente un **trust score (0-100)** per ogni IP:

- **90-100**: Fully Trusted (signed Tailscale, verified proxy)
- **70-89**: High Trust (from trusted proxy, DMZ)
- **50-69**: Medium Trust (private IP, trusted source)
- **20-49**: Low Trust (public IP, minimal verification)
- **0-19**: Untrusted (suspicious pattern, invalid signature)

### Come il Trust Score è Calcolato:

```
Base Score: 50

+ 20: Public IP with direct connection (SourceRemoteAddr)
+ 15: Trusted proxy header (X-Forwarded-For from trusted source)
+ 20: Tailscale IP with valid HMAC signature
+ 10: DMZ IP
+ 10: Whitelisted IP
- 15: X-Public-IP senza firma HMAC
- 20: IP privato spoofato tramite X-Public-IP
```

## 7. Enhanced Logging

Tutti gli eventi di sicurezza includono i dati enterprise:

```json
{
  "timestamp": "2024-11-13T10:30:45Z",
  "ip": "100.64.1.42",
  "ip_source": "x-public-ip",
  "ip_source_type": "tailscale",
  "ip_classification": "trusted",
  "ip_header_signature_valid": true,
  "ip_is_dmz": false,
  "ip_is_tailscale": true,
  "ip_trust_score": 95,
  "ip_validation_details": "Client-reported public IP [HMAC signed]",
  "threat": "XSS_DETECTED",
  "description": "Potential XSS in query parameter",
  "method": "GET",
  "path": "/api/users",
  "blocked": true,
  "blocked_by": "auto"
}
```

## 8. SIEM Integration (Splunk/ELK)

### Splunk Index Configuration

```
[waf]
TRANSFORMS-enterprise = extract_ent_fields
KV_MODE = json
PUNCT = true
ANNOTATE_PUNCT = true
SHOULD_LINEMERGE = false
LINE_BREAKER = [\r\n]+

[extract_ent_fields]
REGEX = (?i)"ip":\s*"([^"]+)"
FORMAT = client_ip::$1
```

### ELK Ingest Pipeline

```json
{
  "description": "WAF Enterprise IP Detection Pipeline",
  "processors": [
    {
      "json": {
        "field": "message",
        "target_field": "waf"
      }
    },
    {
      "set": {
        "field": "event.severity",
        "value": "{{waf.ip_trust_score}}"
      }
    },
    {
      "set": {
        "field": "network.direction",
        "value": "inbound"
      }
    },
    {
      "geoip": {
        "field": "waf.ip",
        "target_field": "geo"
      }
    }
  ]
}
```

## 9. Monitoramento e Alerting

### Dashboard Kibana - Trust Score Trends

```json
{
  "visualization": "line_chart",
  "query": "waf.ip_trust_score",
  "aggregation": "avg(ip_trust_score) per ip_classification",
  "time_range": "24h"
}
```

### Alert - Untrusted Source Activity

```
When: avg(ip_trust_score) < 30
For: 5 minutes
For atleast 10 events
Then: Trigger incident in PagerDuty
```

## 10. Production Deployment Checklist

- [ ] HMAC secrets stored in secure vault (HashiCorp Vault / AWS Secrets Manager)
- [ ] Trusted sources configured and verified
- [ ] DMZ networks properly defined
- [ ] Tailscale network ranges confirmed
- [ ] SIEM pipeline tested with sample events
- [ ] Rate limiting configured per source
- [ ] Backup keys generated and stored securely
- [ ] Audit logging enabled for policy changes
- [ ] Dashboard alerts configured
- [ ] Rotation schedule established (90 days for keys)
- [ ] WAF rules tested in log-only mode first
- [ ] Load testing performed (10x expected traffic)
- [ ] Incident response procedures documented
- [ ] Team trained on new enterprise features

## Troubleshooting

### Invalid HMAC Signature

```bash
# Check client is using correct shared secret
# Verify timestamp is within MaxClockSkew (default 30 seconds)
# Ensure payload includes all required fields

# Debug header values
curl -v https://example.com \
  -H "X-Public-IP: 203.0.113.45" \
  -H "X-HMAC-Signature: <signature>" \
  -H "X-Request-Timestamp: $(date +%s)" \
  2>&1 | grep -E "X-|< X-WAF"
```

### Source Not Recognized

```bash
# List all trusted sources
curl http://api-backend:3000/waf/sources

# Check source IP
curl http://api-backend:3000/waf/sources/by-ip/10.0.1.5

# Verify source is enabled
curl http://api-backend:3000/waf/sources | jq '.sources[] | select(.ip=="10.0.1.5")'
```

### Trust Score Too Low

Check validation logs:
```bash
# Get recent validation logs (requires API endpoint)
curl http://api-backend:3000/waf/validation-logs?ip=100.64.1.42&limit=10
```

## Supporto

Per domande o problemi:
- Consultare la documentazione API: `/waf/docs`
- Abilitare debug logging: `log_level debug` nel Caddyfile
- Contattare il team di sicurezza
