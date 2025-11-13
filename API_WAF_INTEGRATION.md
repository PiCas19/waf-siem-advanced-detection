# WAF-SIEM API Integration Guide

## Overview

The API now fully integrates with the enhanced WAF detector, supporting robust IP extraction with Tailscale/VPN support, comprehensive threat intelligence enrichment, and professional logging with IP source metadata.

## Data Flow: WAF → API → Database

```
┌─────────────────────────────────────────────────────────────────┐
│                      WAF Component                              │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Threat Detection (XSS, SQLi, LFI, SSRF, etc.)            │  │
│  │ ↓                                                         │  │
│  │ Robust IP Extraction:                                    │  │
│  │  1. X-Public-IP (Tailscale/VPN) - HIGHEST PRIORITY      │  │
│  │  2. X-Forwarded-For (trusted proxy only)                │  │
│  │  3. X-Real-IP (trusted proxy only)                      │  │
│  │  4. RemoteAddr (fallback/direct)                        │  │
│  │ ↓                                                         │  │
│  │ WAF Event Payload:                                       │  │
│  │  - ip: "203.0.113.42"                                   │  │
│  │  - ip_source: "x-public-ip"                             │  │
│  │  - ip_trusted: true                                     │  │
│  │  - ip_vpn_reported: true                                │  │
│  │  - threat: "XSS"                                        │  │
│  │  - payload: "<script>alert(1)</script>"                 │  │
│  │  - method, path, user_agent, etc.                       │  │
│  └───────────────────────────────────────────────────────────┘  │
│                            │                                     │
│                   POST /api/waf/event                            │
│                            ↓                                     │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ↓
         ┌──────────────────────────────────────┐
         │        API (stats.go)                │
         │ ┌──────────────────────────────────┐ │
         │ │ 1. extractRealClientIP()         │ │
         │ │    - Check X-Public-IP first    │ │
         │ │    - Fallback to other headers  │ │
         │ │ ↓                                │ │
         │ │ 2. Bind WAFEvent from JSON      │ │
         │ │    - Includes IP metadata       │ │
         │ │ ↓                                │ │
         │ │ 3. Create Log record            │ │
         │ │    - Store all event data       │ │
         │ │    - Include IP source fields   │ │
         │ │ ↓                                │ │
         │ │ 4. EnrichLog() - TI Service     │ │
         │ │    - Geolocation (ip-api.com)   │ │
         │ │    - Reputation (AlienVault)    │ │
         │ │    - Blocklist check            │ │
         │ │ ↓                                │ │
         │ │ 5. Update Log with TI data      │ │
         │ │    - country, asn, isp          │ │
         │ │    - ip_reputation, threat_level│ │
         │ │ ↓                                │ │
         │ │ 6. Broadcast via WebSocket      │ │
         │ │    - Real-time dashboard update │ │
         │ └──────────────────────────────────┘ │
         └──────────────────────────────────────┘
                            │
              ┌─────────────┴─────────────┐
              ↓                           ↓
         ┌─────────────┐          ┌──────────────────┐
         │  Database   │          │  WebSocket Hub   │
         │  (logs)     │          │  (connected      │
         │             │          │   clients)       │
         │ Stores:     │          │                  │
         │ - Event     │          │ Broadcasts:      │
         │ - TI data   │          │ - Event updates  │
         │ - IP source │          │ - Real-time      │
         │   metadata  │          │   alerts         │
         └─────────────┘          └──────────────────┘
                                          │
                                          ↓
                                   ┌──────────────┐
                                   │  Dashboard   │
                                   │  (Frontend)  │
                                   └──────────────┘
```

## 1. WAF Event Payload Structure

The WAF now sends events with enriched IP metadata:

```json
{
  "ip": "203.0.113.42",
  "ip_source": "x-public-ip",
  "ip_trusted": true,
  "ip_vpn_reported": true,
  "threat": "XSS",
  "description": "Cross-Site Scripting attempt detected",
  "method": "GET",
  "path": "/search",
  "query": "q=%3Cscript%3E",
  "user_agent": "Mozilla/5.0...",
  "payload": "<script>alert(1)</script>",
  "timestamp": "2025-01-15T10:30:45Z",
  "blocked": true,
  "blocked_by": "auto"
}
```

## 2. API Processing (NewWAFEventHandler)

### Location
`api/internal/api/stats.go` - Line 112

### Processing Steps

#### Step 1: IP Extraction
```go
realIP := extractRealClientIP(c)
if realIP != event.IP && realIP != "" {
    event.IP = realIP
}
```

**Priority Order:**
1. `X-Public-IP` - Client self-reported (Tailscale/VPN)
2. `X-Forwarded-For` - Proxy chain (first IP)
3. `CF-Connecting-IP` - Cloudflare
4. `X-Real-IP` - Nginx/Apache
5. `X-Client-IP` - Generic proxy

#### Step 2: WAF Event Binding
```go
var event websocket.WAFEvent
if err := c.ShouldBindJSON(&event); err != nil {
    // Handle error
}
```

The `WAFEvent` struct now includes IP metadata fields:
- `IPSource` - How IP was extracted
- `IPTrusted` - Source trustworthiness
- `IPVPNReport` - Tailscale/VPN self-report flag

#### Step 3: Log Creation
```go
log := models.Log{
    ThreatType:        event.Threat,
    ClientIP:          event.IP,
    ClientIPSource:    event.IPSource,
    ClientIPTrusted:   event.IPTrusted,
    ClientIPVPNReport: event.IPVPNReport,
    // ... other fields
}
db.Create(&log)
```

#### Step 4: Threat Intelligence Enrichment
```go
if err := tiService.EnrichLog(&log); err != nil {
    // Log enrichment error
}
```

The TI service enriches with:
- **Geolocation**: Country, ASN, ISP (ip-api.com)
- **Reputation**: IP reputation score, threat level (AlienVault OTX)
- **Blocklist**: Check against known malicious IP lists

#### Step 5: Database Update
```go
db.Model(&models.Log{}).Where("id = ?", log.ID).Updates(map[string]interface{}{
    "country":         log.Country,
    "asn":             log.ASN,
    "isp":             log.ISP,
    "ip_reputation":   log.IPReputation,
    "threat_level":    log.ThreatLevel,
    "is_on_blocklist": log.IsOnBlocklist,
    "enriched_at":     log.EnrichedAt,
})
```

#### Step 6: Real-time Broadcasting
```go
websocket.Broadcast(event)
```

Sends event to all connected WebSocket clients for real-time dashboard updates.

## 3. Log Model Enhancement

### New IP Source Fields

```go
type Log struct {
    // ... existing fields ...

    // IP Source Metadata (from WAF)
    ClientIPSource    string // "x-public-ip", "x-forwarded-for", "x-real-ip", "remote-addr"
    ClientIPTrusted   bool   // Is this a trusted source?
    ClientIPVPNReport bool   // Self-reported from Tailscale/VPN?

    // Threat Intelligence
    IPReputation      *int   // 0-100 score
    IsMalicious       bool   // Known malicious IP?
    Country           string // ISO country code
    ASN               string // Autonomous System Number
    ISP               string // Internet Service Provider
    ThreatLevel       string // "critical", "high", "medium", "low", "none"
    ThreatSource      string // "alienvault-otx", "ip-api.com", etc.
    IsOnBlocklist     bool   // On known blocklists?
    BlocklistName     string // Which blocklist?
    AbuseReports      *int   // Abuse report count
    EnrichedAt        *time.Time // When enriched?
}
```

## 4. Threat Intelligence Enrichment Pipeline

### Location
`api/internal/threatintel/service.go`

### Enrichment Process

```
EnrichLog(log *Log)
  │
  ├─→ Check if IP is private/reserved
  │
  ├─→ Check in-memory cache (24h TTL)
  │   └─→ If cached: Apply and return
  │
  ├─→ Query ip-api.com (45 req/min free)
  │   └─→ Get: Country, ISP, ASN
  │
  ├─→ Query AlienVault OTX (unlimited free)
  │   └─→ Get: Threat count, pulses, reputation
  │   └─→ Calculate: reputation score (0-100)
  │   └─→ Set: threat_level based on reputation
  │
  ├─→ Check local blocklist database
  │   └─→ Query: BlockedIP table
  │   └─→ Match: (IP + ThreatType) OR (IP + "GLOBAL")
  │
  ├─→ Cache result (24h TTL)
  │
  └─→ Apply to Log model
```

### Reputation Calculation

```go
reputation = 20 + (threat_count × 10) + (pulses × 5)
if reputation > 100 {
    reputation = 100
}

threatLevel = calculateThreatLevel(reputation)
// "none" (0-20), "low" (21-40), "medium" (41-60), "high" (61-80), "critical" (81-100)
```

### Private IP Handling

- **Private IPs (RFC1918)**: Geolocation only, no reputation
- **Reserved IPs (CGN)**: Treated as safe, no reputation
- **Public IPs**: Full enrichment

## 5. Integration Examples

### Example 1: Tailscale/VPN Client Attack

**WAF sends:**
```json
{
  "ip": "203.0.113.42",
  "ip_source": "x-public-ip",
  "ip_trusted": true,
  "ip_vpn_reported": true,
  "threat": "SQL_INJECTION",
  "payload": "' OR '1'='1",
  "blocked": true
}
```

**API processes:**
1. Recognizes X-Public-IP (highest priority)
2. Creates Log with ClientIPVPNReport=true
3. Enriches from AlienVault OTX
4. Finds reputation data
5. Broadcasts to dashboard with "VPN Client Attack" label

**Dashboard shows:**
- IP: 203.0.113.42
- Source: Tailscale/VPN (self-reported)
- Threat: SQL_INJECTION
- Reputation: 65 (High risk)
- Country: US
- ISP: AlternC ISP

### Example 2: Proxy Chain Attack

**WAF sends:**
```json
{
  "ip": "192.0.2.1",
  "ip_source": "x-forwarded-for",
  "ip_trusted": true,
  "ip_vpn_reported": false,
  "threat": "XSS",
  "payload": "<script>alert('xss')</script>",
  "blocked": true
}
```

**API processes:**
1. Detects X-Forwarded-For (from trusted proxy)
2. Marks as trusted source
3. Enriches IP reputation
4. Checks blocklist

**Dashboard shows:**
- IP: 192.0.2.1
- Source: X-Forwarded-For (trusted proxy)
- Proxy Chain: Visible in logs
- Threat: XSS
- Reputation: 45 (Medium)

### Example 3: Direct Connection (RemoteAddr)

**WAF sends:**
```json
{
  "ip": "198.51.100.5",
  "ip_source": "remote-addr",
  "ip_trusted": true,
  "ip_vpn_reported": false,
  "threat": "LFI",
  "payload": "../../../etc/passwd",
  "blocked": true
}
```

**API processes:**
1. Uses RemoteAddr (direct connection)
2. Always trusted (TCP layer)
3. Full enrichment
4. Reputation check

## 6. Configuration

### Caddyfile (WAF)
```caddy
waf {
    rules_file /etc/caddy/rules.json
    log_file /var/log/waf.log
    api_endpoint http://localhost:3000/api

    # Configure trusted proxies
    trusted_proxies 127.0.0.1 10.0.0.0/8 192.168.1.0/24
}
```

### API Environment
```bash
DATABASE_URL=sqlite:waf_siem.db
PORT=3000
LOG_LEVEL=info
```

## 7. Dashboard Integration

### Real-time Events
- WAFEvent includes IP metadata
- WebSocket broadcasts include source info
- Dashboard can filter/sort by IP source

### Filters Available
```javascript
// Filter by IP source
events.filter(e => e.ip_source === "x-public-ip")

// Filter by threat level
events.filter(e => e.threat_level === "critical")

// Filter by VPN clients
events.filter(e => e.ip_vpn_reported === true)

// Filter by blocklist
events.filter(e => e.is_on_blocklist === true)
```

### Visualizations
- IP reputation heatmap
- Geographic distribution (country)
- Threat level distribution
- IP source breakdown
- VPN vs Direct connection comparison

## 8. Threat Intelligence Sources

### Primary Sources
1. **ip-api.com** (45 req/min free)
   - Geolocation
   - ISP/ASN
   - Timezone

2. **AlienVault OTX** (unlimited free)
   - IP reputation
   - Threat indicators
   - Abuse reports
   - No API key required

3. **Local Blocklist** (database)
   - Threat-specific blocks
   - Temporary + permanent blocks
   - Expiration support

## 9. Performance Considerations

### Caching Strategy
- 24-hour in-memory cache per IP
- Reduces external API calls
- Survives application restart
- Per-IP basis (no bulk caching)

### Rate Limits
- ip-api.com: 45 requests/minute
- AlienVault OTX: Unlimited
- Total request time: ~2-3 seconds per IP

### Database Indexes
- Log.ClientIP (indexed)
- BlockedIP.IPAddress (indexed)
- Composite index on (IPAddress, Description)

## 10. Troubleshooting

### Issue: IP not enriched
**Solution**: Check TI service logs for API failures, verify database connection

### Issue: Wrong IP extracted
**Solution**: Verify trusted_proxies in Caddyfile, check proxy header names

### Issue: VPN IP not detected
**Solution**: Verify client sends X-Public-IP header, check WAF logs for header reception

### Issue: Slow enrichment
**Solution**: Check external API response times, clear cache if needed

## 11. Future Enhancements

- [ ] Support for additional TI providers (VirusTotal, MaxMind)
- [ ] Batch IP enrichment for bulk imports
- [ ] Custom TI rules per threat type
- [ ] ML-based anomaly detection
- [ ] GeoIP heatmap visualization
- [ ] Automatic response actions (auto-block, notify)

## Summary

The WAF-SIEM API integration now provides:
✅ Robust client IP extraction (Tailscale/VPN support)
✅ Comprehensive threat intelligence enrichment
✅ Real-time WebSocket broadcasting
✅ Professional IP source tracking
✅ Geolocation and reputation data
✅ Blocklist checking and enforcement
✅ Performance optimized caching
✅ Complete dashboard integration
