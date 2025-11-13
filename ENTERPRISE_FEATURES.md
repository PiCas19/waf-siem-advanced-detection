# 🚀 Enterprise-Grade WAF: Advanced IP Detection & Source Trust Management

Hai un **WAF production-ready** con capacità **enterprise-grade** per ambienti complessi con Tailscale, DMZ, reverse proxy, e SIEM integration.

## ✨ Cosa abbiamo Implementato

### 1. **IP Detection Intelligence** 🧠
- **Pubblico vs Privato**: Distingue automaticamente IP pubblici, privati, riservati
- **Tailscale Detection**: Riconosce IP Tailscale (100.64.0.0/10) con validazione firma
- **DMZ Detection**: Identifica IP in zona DMZ e applica policies diverse
- **Source-based Trust**: Ogni IP ha un trust score (0-100) basato su:
  - Metodo di estrazione (direct, proxy, self-reported)
  - Firma HMAC valida
  - Whitelist/blacklist status
  - Localizzazione geografica
  - Tipo di sorgente (Tailscale, proxy, DMZ, ecc.)

### 2. **HMAC Header Validation** 🔐
- **Firma Digitale**: Header `X-Public-IP` firmati con HMAC-SHA256
- **Replay Attack Protection**: Validazione timestamp con clock skew configurable
- **Antifalsificazione**: Impossibile spooffare IP da sorgenti non fidate
- **Key Rotation**: Gestione automatica di rotazione chiavi (90 giorni)
- **Per-Source Secrets**: Chiavi HMAC uniche per ogni sorgente trusted

### 3. **Trusted Source Management** 🏢
- **Policy-based Configuration**: Definisci policies di trust per:
  - Reverse Proxy (Nginx, Apache, Caddy)
  - Load Balancer (AWS ALB/NLB, Azure LB)
  - DMZ Appliances
  - Tailscale Network
  - VPN Gateways
  - Custom Sources

- **Per-Source Configuration**:
  - Headers permessi (X-Public-IP, X-Forwarded-For, X-Real-IP)
  - Rate limiting per IP
  - Auto-block dopo N errori di validazione
  - Ubicazione geografica e country tagging

### 4. **Enhanced Logging & SIEM** 📊
Ogni evento WAF include dati enterprise:
```json
{
  "ip": "100.64.1.42",
  "ip_source": "x-public-ip",
  "ip_source_type": "tailscale",
  "ip_classification": "trusted",
  "ip_header_signature_valid": true,
  "ip_is_dmz": false,
  "ip_is_tailscale": true,
  "ip_trust_score": 95,
  "threat": "XSS_DETECTED",
  "blocked": true
}
```

### 5. **API Endpoints** 🔌

#### Trusted Sources Management
```bash
GET    /waf/sources              # List all sources
GET    /waf/sources/:id          # Get source by ID
POST   /waf/sources              # Create source
PUT    /waf/sources/:id          # Update source
DELETE /waf/sources/:id          # Delete source
POST   /waf/sources/:id/verify   # Verify source
GET    /waf/sources/by-ip/:ip    # Get by IP
```

#### HMAC Key Management
```bash
GET    /waf/hmac-keys            # List all keys
POST   /waf/hmac-keys            # Create key
DELETE /waf/hmac-keys/:id        # Delete key
POST   /waf/hmac-keys/:id/rotate # Rotate key
```

## 📁 Nuovi File Creati

### WAF Side (Go)
1. **`waf/internal/ipextract/header_validator.go`** (650 lines)
   - HMAC signature validation
   - DMZ/Tailscale detection
   - Trust scoring logic
   - Header cryptographic validation

2. **`waf/internal/ipextract/trusted_sources.go`** (450 lines)
   - TrustedSource struct
   - TrustedSourcePolicy management
   - GlobalTrustedSourceManager
   - Per-source configuration

3. **`waf/internal/ipextract/header_validator_test.go`** (350 lines)
   - Comprehensive test suite
   - HMAC validation tests
   - DMZ/Tailscale detection tests
   - Trust score calculation tests
   - Benchmarks for performance

4. **`waf/ENTERPRISE_SETUP.md`** (400 lines)
   - Complete setup guide
   - Configuration examples
   - HMAC generation examples
   - Troubleshooting guide

### API Side (Go)
1. **`api/internal/api/trusted_sources.go`** (400 lines)
   - REST endpoints for sources
   - HMAC key management
   - Source verification
   - Database operations

2. **`api/internal/database/models/trusted_source.go`** (180 lines)
   - TrustedSource model
   - HMACKey model
   - SourceValidationLog model
   - TrustedSourcePolicy model

### Modified Files
- **`waf/pkg/waf/middleware.go`**: +150 lines
  - Enterprise configuration fields
  - HMAC/DMZ/Tailscale initialization
  - Enhanced IP extraction
  - Enterprise event payload
  - Caddyfile parsing for new directives

- **`waf/internal/ipextract/ip_extractor.go`**: +90 lines
  - ExtractClientIPWithPolicy function
  - Enhanced imports (http, time)
  - Integration with enterprise components

## 🔧 Configurazione Caddyfile

```caddyfile
example.com {
    waf {
        # Standard config
        log_file /var/log/waf/events.json
        api_endpoint http://api:3000

        # Enterprise IP Detection
        enable_hmac_signature_validation true
        hmac_shared_secret "your-secret-key-here"
        trusted_proxies 10.0.1.5 10.0.1.6

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

## 📊 Flusso di Validazione

```
Request →
  1. Extract IP using standard methods
  2. If X-Public-IP:
     - Validate HMAC signature
     - Check timestamp (clock skew)
     - Verify source IP is trusted
  3. Classify IP type (Tailscale, DMZ, public, private)
  4. Calculate trust score
  5. Apply policies (blocklist, whitelist, rate limiting)
  6. Log enhanced event with enterprise metadata
  → Response
```

## 🎯 Trust Score Calculation

| Fattore | Punti |
|---------|-------|
| Base | 50 |
| Public IP (direct connection) | +20 |
| Trusted proxy (X-Forwarded-For) | +15 |
| Tailscale con firma valida | +20 |
| DMZ IP | +10 |
| Whitelisted | +10 |
| X-Public-IP senza firma | -15 |
| IP privato spoofato | -20 |

**Interpretazione:**
- 90-100: **Fully Trusted** ✅
- 70-89: **High Trust** 🟢
- 50-69: **Medium Trust** 🟡
- 20-49: **Low Trust** 🟠
- 0-19: **Untrusted** ❌

## 🚀 Come Iniziare

### 1. Compilazione

```bash
cd waf
go build -o waf ./cmd/caddy-waf/

# Or with Caddy module
go run cmd/caddy-waf/main.go
```

### 2. Configurazione Database (API)

```bash
# Create tables for trusted sources
go run api/cmd/main.go migrate

# Or manually
sqlite3 waf.db < api/migrations/trusted_sources.sql
```

### 3. Setup Trusted Sources

```bash
# Create Tailscale source
curl -X POST http://localhost:3000/waf/sources \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Tailscale VPN",
    "type": "tailscale",
    "ip_range": "100.64.0.0/10",
    "trusts_x_public_ip": true,
    "require_signature": true
  }'

# Create DMZ reverse proxy
curl -X POST http://localhost:3000/waf/sources \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Nginx DMZ",
    "type": "reverse_proxy",
    "ip": "10.0.1.5",
    "trusts_x_forwarded_for": true
  }'
```

### 4. Genera Client HMAC

```go
package main

import (
    "fmt"
    "github.com/PiCas19/waf-siem-advanced-detection/waf/internal/ipextract"
)

func main() {
    sig, ts := ipextract.GenerateClientSignature(
        "203.0.113.45",
        "your-shared-secret",
        map[string]string{},
    )

    fmt.Printf("X-HMAC-Signature: %s\n", sig)
    fmt.Printf("X-Request-Timestamp: %s\n", ts)
}
```

### 5. Invia Request Firmati

```bash
curl -X GET http://example.com/api/data \
  -H "X-Public-IP: 203.0.113.45" \
  -H "X-HMAC-Signature: $(generate-signature)" \
  -H "X-Request-Timestamp: $(date +%s)"
```

## 📈 Monitoraggio & Alerting

### Metriche Chiave
- Trust score distribution
- Blocked vs allowed by source type
- HMAC validation success rate
- DMZ vs Tailscale vs public traffic split
- Source error rates

### Alert Suggeriti
- Trust score < 30 per source
- HMAC validation failures > 10/min
- DMZ IP accessing sensitive endpoints
- Untrusted source exceeds rate limit
- Key rotation due (90 days)

## 🔒 Security Best Practices

1. **Secrets Management**
   - Store HMAC secrets in HashiCorp Vault
   - Never commit secrets to git
   - Rotate every 90 days
   - Use different secrets per source

2. **Clock Synchronization**
   - Ensure NTP sync (< 1 second drift)
   - Set MaxClockSkew conservatively (30 sec)
   - Monitor clock drift in metrics

3. **Rate Limiting**
   - Set MaxRequestsPerMin per source
   - Implement global rate limits
   - Use exponential backoff

4. **Audit Logging**
   - Enable all source verification logs
   - Forward to SIEM
   - Set retention policy (90 days min)
   - Alert on configuration changes

## 📚 Documentazione

- **`waf/ENTERPRISE_SETUP.md`** - Setup completo e troubleshooting
- **`api/internal/api/trusted_sources.go`** - API documentation (godoc)
- **`waf/internal/ipextract/header_validator.go`** - HMAC validation docs
- **`waf/internal/ipextract/trusted_sources.go`** - Policy management docs

## ✅ Checklist Production

- [ ] HMAC secrets in vault
- [ ] Trusted sources configured and verified
- [ ] DMZ networks properly defined
- [ ] Tailscale ranges confirmed (100.64.0.0/10)
- [ ] SIEM pipeline tested
- [ ] Rate limiting configured
- [ ] Backup keys generated
- [ ] Audit logging enabled
- [ ] Alerts configured
- [ ] Key rotation schedule set
- [ ] Load testing passed (10x expected traffic)
- [ ] Team trained

## 🐛 Troubleshooting

### Invalid HMAC Signature
```bash
# Check timestamp freshness
date +%s  # Current timestamp

# Verify shared secret
echo -n "your-payload" | openssl dgst -sha256 -hmac "your-secret"

# Check request in debug mode
curl -v -H "X-HMAC-Signature: ..." 2>&1 | grep "X-WAF"
```

### Source Not Recognized
```bash
# List sources
curl http://localhost:3000/waf/sources | jq

# Check by IP
curl http://localhost:3000/waf/sources/by-ip/10.0.1.5
```

### Trust Score Low
```bash
# Enable debug logging
# Check validation logs in SIEM
# Verify signature, timestamp, source IP
```

## 📞 Support

- Consultare la documentazione nei file .md
- Abilitare debug logging nel Caddyfile
- Controllare i log WAF per details
- Verificare SIEM per validation logs

---

**Congratulazioni!** 🎉 Il tuo WAF è ora **enterprise-grade** con capacità di:
- ✅ Distinguere IP pubblico/privato/Tailscale/DMZ con certezza
- ✅ Validare fiducia della fonte con HMAC firmati
- ✅ Integrare con ambienti complessi (Tailscale, reverse proxy, SIEM)
- ✅ Gestire policy di trust centralizzate via API
- ✅ Loggare e monitorare con dati enterprise
