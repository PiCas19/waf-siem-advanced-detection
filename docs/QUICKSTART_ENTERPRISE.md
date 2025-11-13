# Enterprise IP Detection - Quick Start Guide

## 5-Minute Setup

### Step 1: Verify Build

```bash
# Build WAF module
cd waf
go build ./...
echo "✅ WAF builds successfully"

# Build API module
cd ../api
go build ./...
echo "✅ API builds successfully"
```

### Step 2: Configure Shared Secret

Edit `waf/Caddyfile` (port 8080 section):

```caddyfile
hmac_shared_secret "your-secret-here-minimum-32-characters"
```

**Generate a strong secret**:
```bash
openssl rand -hex 32
# Output: 49f2cd7271d9c1e575ee0d9d7a29e8e2ed23460a75e61fc9ffd73efb6d3ef962
```

### Step 3: Start Services

```bash
# Start API server
cd api
go run cmd/api-server/main.go

# In another terminal, start WAF
cd waf
xcaddy run -c Caddyfile
```

### Step 4: Create Trusted Source (via API)

```bash
curl -X POST http://localhost:8081/api/waf/sources \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Reverse Proxy",
    "type": "reverse_proxy",
    "ip": "203.0.113.50",
    "ip_range": "203.0.113.0/24",
    "trusts_x_public_ip": true,
    "trusts_x_forwarded_for": true,
    "require_signature": true,
    "max_requests_per_min": 1000
  }'
```

### Step 5: Test with HMAC Signature

```bash
#!/bin/bash

# Configuration
PUBLIC_IP="100.115.217.37"
SHARED_SECRET="49f2cd7271d9c1e575ee0d9d7a29e8e2ed23460a75e61fc9ffd73efb6d3ef962"
METHOD="GET"
PATH="/?secret=admin_secret_access_12345"
TIMESTAMP=$(date +%s)

# Generate signature
PAYLOAD="${PUBLIC_IP}|${TIMESTAMP}|${METHOD}|${PATH}"
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SHARED_SECRET" -hex | cut -d' ' -f2)

# Make request
curl -v "https://caddy-waf.tail95e242.ts.net/${PATH}" \
  -H "X-Public-IP: ${PUBLIC_IP}" \
  -H "X-HMAC-Signature: ${SIGNATURE}" \
  -H "X-Request-Timestamp: ${TIMESTAMP}"
```

## Common Configuration Patterns

### Pattern 1: Tailscale Network (WAN)

```caddyfile
:8080 {
    handle {
        waf {
            enable_hmac_signature_validation true
            hmac_shared_secret "your-secret"
            enable_tailscale_detection true
            tailscale_networks 100.64.0.0/10
            trusted_proxies 127.0.0.1 ::1
        }
    }
}
```

### Pattern 2: Internal LAN

```caddyfile
:8443 {
    handle {
        waf {
            trusted_proxies 127.0.0.1 ::1 172.16.0.0/12 10.0.0.0/8
        }
    }
}
```

### Pattern 3: DMZ with HMAC

```caddyfile
:9000 {
    handle {
        waf {
            enable_hmac_signature_validation true
            hmac_shared_secret "dmz-secret"
            enable_dmz_detection true
            dmz_networks 172.16.0.0/12 192.168.100.0/24
            trusted_proxies 127.0.0.1 ::1
        }
    }
}
```

## API Quick Reference

### List Trusted Sources
```bash
curl http://localhost:8081/api/waf/sources
```

### Get Source by ID
```bash
curl http://localhost:8081/api/waf/sources/{id}
```

### Lookup Source by IP
```bash
curl http://localhost:8081/api/waf/sources/by-ip/100.115.217.37
```

### Verify Source
```bash
curl -X POST http://localhost:8081/api/waf/sources/{id}/verify
```

### Create HMAC Key
```bash
curl -X POST http://localhost:8081/api/waf/hmac-keys \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Tailscale Key",
    "secret": "your-shared-secret",
    "trusted_source_id": "source-id",
    "rotation_interval": 90,
    "is_active": true
  }'
```

### Rotate HMAC Key
```bash
curl -X POST http://localhost:8081/api/waf/hmac-keys/{id}/rotate
```

## Monitoring & Debugging

### Check Logs for Trust Scores

```bash
# Watch WAF logs (Mac/Linux)
tail -f /var/log/caddy/waf_wan.log | jq '.ip_trust_score'

# Or with grep
grep "ip_trust_score" /var/log/caddy/waf_wan.log | tail -20
```

### Verify HMAC Validation

```bash
# Look for signature validation results
grep "signature_valid" /var/log/caddy/waf_wan.log

# Check for failed signatures
grep "signature_valid.*false" /var/log/caddy/waf_wan.log
```

### Monitor IP Classification

```bash
# Check detected IP sources
grep "ip_source_type" /var/log/caddy/waf_wan.log | sort | uniq -c

# Should show:
# - "tailscale" for 100.64.0.0/10
# - "dmz" for configured DMZ ranges
# - "private" for RFC 1918
# - "public" for internet IPs
```

## Common Issues & Solutions

### Issue: Signature Always Invalid

**Solution**: Verify shared secret matches exactly
```bash
# In Go code
sharedSecret := "49f2cd7271d9c1e575ee0d9d7a29e8e2ed23460a75e61fc9ffd73efb6d3ef962"

# In Caddyfile
hmac_shared_secret "49f2cd7271d9c1e575ee0d9d7a29e8e2ed23460a75e61fc9ffd73efb6d3ef962"

# Use diff or hexdump to compare
echo -n "secret1" | md5sum
echo -n "secret2" | md5sum
```

### Issue: Tailscale IPs Not Detected

**Solution**: Ensure network range is correct
```caddyfile
# Correct
enable_tailscale_detection true
tailscale_networks 100.64.0.0/10

# Test detection
curl http://localhost:8081/api/waf/sources/by-ip/100.115.217.37
# Should show: "ip_source_type": "tailscale"
```

### Issue: Clock Skew Errors

**Solution**: Synchronize system clocks
```bash
# Check system time
date
ntpdate -q time.nist.gov

# Sync time (Linux)
sudo ntpdate -s time.nist.gov

# Sync time (Mac)
sudo sntp -S time.apple.com
```

### Issue: Database Not Initialized

**Solution**: Run migrations
```go
// In your API startup code
db.AutoMigrate(
    &models.TrustedSource{},
    &models.HMACKey{},
    &models.SourceValidationLog{},
    &models.TrustedSourcePolicy{},
)
```

## Performance Tips

1. **Cache DNS**: Disable DNS lookups in Caddyfile
   ```caddyfile
   servers {
       strict_sni_host false
   }
   ```

2. **Enable HTTP/2**: Already configured in Caddyfile
   ```caddyfile
   servers {
       protocols h1 h2 h3
   }
   ```

3. **Optimize Database**: Add indexes to frequent queries
   ```bash
   # In database migrations
   CREATE INDEX idx_trusted_source_ip ON trusted_sources(ip);
   CREATE INDEX idx_trusted_source_enabled ON trusted_sources(is_enabled);
   ```

4. **Monitor Signature Validation**: Normally <50 microseconds per request

## Testing Checklist

- [ ] WAF compiles without errors
- [ ] API compiles without errors
- [ ] Database migrations run successfully
- [ ] Default trusted source policy created
- [ ] Reverse proxy added as trusted source
- [ ] HMAC shared secret configured
- [ ] Tailscale network range added
- [ ] Test request with valid signature passes
- [ ] Test request with invalid signature blocked
- [ ] Trust score visible in logs
- [ ] IP classification correct (tailscale/private/dmz/public)
- [ ] SIEM events include new IP metadata fields

## Next Steps

1. **Read Full Documentation**: See `docs/ENTERPRISE_IP_DETECTION.md`
2. **Review Implementation**: Check git commits `c497a50` and earlier
3. **Setup Dashboard**: Add trusted sources via UI (if implemented)
4. **Configure SIEM**: Map new JSON fields to your SIEM
5. **Test Integration**: Use provided cURL examples
6. **Monitor Metrics**: Track trust score distribution
7. **Tune Thresholds**: Adjust based on traffic patterns

## References

- [Full Enterprise Guide](ENTERPRISE_IP_DETECTION.md)
- [Implementation Status](IMPLEMENTATION_STATUS.md)
- [Architecture Diagram](architecture.md)
- [Caddyfile Configuration](../waf/Caddyfile)
- [API Source Code](../api/internal/api/trusted_sources.go)
- [Header Validator Code](../waf/internal/ipextract/header_validator.go)

## Support

For questions or issues:
1. Check ENTERPRISE_IP_DETECTION.md troubleshooting section
2. Review git commit history for recent changes
3. Check API endpoint documentation
4. Verify Caddyfile syntax with `caddy validate`
5. Review WAF logs for detailed error messages

---

**Ready to go!** Start with Step 1 and you'll have enterprise IP detection running in minutes.
