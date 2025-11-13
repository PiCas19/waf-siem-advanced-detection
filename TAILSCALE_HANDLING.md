# Tailscale/VPN IP Handling Guide

## 🎯 Overview

This guide explains how the WAF-SIEM system handles Tailscale and other VPN clients that operate on reserved IP ranges.

## 📍 The Tailscale IP Problem

### IP Ranges
- **Tailscale Internal Network**: 100.64.0.0/10 (RFC 6598 - Carrier Grade NAT)
- **Example IP**: 100.115.217.37
- **Issue**: This range is reserved and appears as "private" or "internal" to external IP lookup services

### Classic Log Output (❌ Before Fix)
```
IP|100.115.217.37|Threat|Detected|Blocked
Country|PRIVATE
ISP|Internal/Private Network
ThreatLevel|low
ThreatSource|internal
```

**Problem**: Doesn't indicate this is from a Tailscale VPN client!

### Improved Log Output (✅ After V1 Fix)
```
IP|100.115.217.37|ClientIPVPNReport|true|ClientIPSource|x-public-ip|ClientIPPublic|203.0.113.42
Threat|Detected|Blocked
Country|VPN/TAILSCALE (or real country if public IP geolocated)
ISP|Tailscale VPN Network (or real ISP from public IP)
ThreatLevel|low
ThreatSource|tailscale-vpn (or ip-api.com for real geolocation)
```

**Better**: Clearly identifies Tailscale VPN client!

### Enhanced Log Output (✅ After V2 Fix - Real Geolocation)
```
IP|100.115.217.37|ClientIPVPNReport|true|ClientIPSource|x-public-ip|ClientIPPublic|203.0.113.42
Threat|Detected|Blocked
Country|IT
ISP|Vodafone Italia
ASN|AS3352
ThreatLevel|low
ThreatSource|ip-api.com (Tailscale public IP)
```

**Best**: Shows the REAL country/ISP from the public IP while still flagging it as low-risk VPN!

## 🔍 How It Works

### 1. Client Detection

Tailscale clients are detected when they meet BOTH conditions:
1. Send `X-Public-IP` header (self-reported public IP)
2. Have a reserved IP in range 100.64.0.0/10

```
Client (Tailscale)
    ↓
Send X-Public-IP header
    ↓
Request forwarded through WAF
    ↓
WAF extracts: ip_source="x-public-ip", ip_vpn_reported=true
    ↓
API receives with VPN flag set
```

### 2. Threat Intelligence Enrichment

**TI Service Logic** (`threatintel/service.go`):

```go
if isReserved && isTailscaleVPN && log.ClientIPPublic != "" {
    // This is a Tailscale client - try to geolocate the reported public IP
    publicGeoData := geolocate(log.ClientIPPublic)  // Use ip-api.com
    if publicGeoData != nil {
        // Use real geolocation from public IP
        data.Country = publicGeoData.Country     // e.g., "IT"
        data.ISP = publicGeoData.ISP             // e.g., "Vodafone Italia"
        data.ThreatSource = "ip-api.com (Tailscale public IP)"
        data.ThreatLevel = "low"  // Still low-risk because it's from VPN

        // Also check reputation of the public IP
        reputation := checkAlienVaultOTX(log.ClientIPPublic)
        if reputation != nil {
            data.IsMalicious = reputation.IsMalicious
            data.IPReputation = reputation.IPReputation
        }
    }
} else if isReserved && isTailscaleVPN {
    // Tailscale client but no public IP reported - use default
    data.Country = "VPN/TAILSCALE"
    data.ISP = "Tailscale VPN Network"
    data.ThreatSource = "tailscale-vpn"
    data.ThreatLevel = "low"
}
```

### 3. Logging

When a Tailscale client is detected:
```
[INFO] *** TAILSCALE/VPN CLIENT DETECTED *** Internal IP=100.115.217.37, Public IP=203.0.113.42, Source=x-public-ip, Trusted=true
[INFO] X-Public-IP (Tailscale/VPN client public IP): 203.0.113.42
[INFO] Tailscale VPN client detected - attempting to geolocate reported public IP: 203.0.113.42
[INFO] Successfully geolocated Tailscale public IP 203.0.113.42: Country=IT, ISP=Vodafone Italia, ASN=AS3352
[INFO] AlienVault OTX for Tailscale public IP 203.0.113.42: reputation=15, isMalicious=false
```

## 📋 Database Fields

### IP Metadata Fields

```go
ClientIPSource: "x-public-ip"     // How the IP was extracted
ClientIPTrusted: true             // Is it from a trusted source?
ClientIPVPNReport: true           // Self-reported from Tailscale/VPN?
ClientIPPublic: "203.0.113.42"    // The public IP reported by Tailscale client
```

### Threat Intelligence Fields

```go
Country: "VPN/TAILSCALE"          // Country field shows VPN
ISP: "Tailscale VPN Network"      // ISP field shows VPN
ThreatSource: "tailscale-vpn"     // Source is tailscale-vpn
ThreatLevel: "low"                // VPN clients are low risk
```

## 🎯 Query Examples

### Find attacks from Tailscale clients
```sql
SELECT * FROM logs
WHERE client_ip_vpn_report = true
  AND threat_level = 'critical'
ORDER BY created_at DESC;
```

### Differentiate Tailscale vs other VPN
```sql
SELECT client_ip_source, COUNT(*) as count, AVG(ip_reputation) as avg_rep
FROM logs
WHERE client_ip_vpn_report = true
GROUP BY client_ip_source;
```

### Find suspicious Tailscale activity
```sql
SELECT * FROM logs
WHERE client_ip_vpn_report = true
  AND country = 'VPN/TAILSCALE'
  AND threat_type IN ('SQL_INJECTION', 'COMMAND_INJECTION', 'XXE')
ORDER BY created_at DESC;
```

## 🔧 Configuration

### Caddyfile (WAF)
```caddy
waf {
    # X-Public-IP from Tailscale clients gets highest priority
    # No special configuration needed - automatic!
    api_endpoint http://localhost:3000/api
}
```

### Client (Tailscale)
```javascript
// Tailscale client sending X-Public-IP header
async function getPublicIP() {
    const response = await fetch('https://api.ipify.org?format=json');
    const data = await response.json();
    return data.ip; // e.g., "203.0.113.42"
}

const publicIP = await getPublicIP();

// Send request with self-reported public IP
fetch('/api/resource', {
    headers: {
        'X-Public-IP': publicIP
    }
});
```

## 🔐 Security Implications

### Why Tailscale clients are trusted
1. **Self-reporting**: Clients explicitly send X-Public-IP header
2. **Encrypted tunnel**: All traffic through Tailscale is encrypted
3. **Authentication**: Requires Tailscale credentials to access
4. **No IP spoofing**: X-Public-IP must match actual IP (or Tailscale will reject)

### Risk Assessment
- **Threat Level**: LOW (but individual threat types still assessed)
- **Default Action**: Log only (not block)
- **Rate Limiting**: Same as other clients
- **Reputation**: Not applicable (no public reputation for Tailscale IPs)

## 📊 Dashboard Display

### Suggested Dashboard Changes

```javascript
// Filter UI
{
    name: "IP Source",
    options: [
        { label: "Tailscale/VPN", value: "client_ip_vpn_report = true" },
        { label: "Proxy", value: "client_ip_source = 'x-forwarded-for'" },
        { label: "Direct", value: "client_ip_source = 'remote-addr'" }
    ]
}

// Card display for Tailscale attacks
function displayTailscaleEvent(event) {
    if (event.client_ip_vpn_report) {
        return `
            <div class="tailscale-badge">
                <i class="vpn-icon"></i> Tailscale Client
                <div>Internal IP: ${event.client_ip}</div>
            </div>
        `;
    }
}
```

### Metrics

```javascript
// Dashboard stats
{
    "total_attacks": 150,
    "from_tailscale": 15,        // 10% from VPN
    "from_proxy": 50,             // 33% from proxies
    "from_direct": 85             // 57% direct
}
```

## 🐛 Debugging

### Check if Tailscale client is sending header
```bash
curl -H "X-Public-IP: 203.0.113.42" \
     -H "User-Agent: Mozilla/5.0" \
     http://waf.example.com/api/resource
```

### Check WAF logs for VPN detection
```bash
grep "TAILSCALE\|VPN CLIENT" /var/log/waf.log
```

### Check database for VPN flag
```bash
sqlite3 waf_siem.db "SELECT client_ip, client_ip_vpn_report, country, threat_source FROM logs LIMIT 10;"
```

## 📈 Analytics Examples

### Weekly VPN attack breakdown
```sql
SELECT
    DATE(created_at) as date,
    SUM(CASE WHEN client_ip_vpn_report THEN 1 ELSE 0 END) as tailscale_attacks,
    SUM(CASE WHEN NOT client_ip_vpn_report THEN 1 ELSE 0 END) as other_attacks,
    COUNT(*) as total
FROM logs
WHERE created_at >= datetime('now', '-7 days')
GROUP BY DATE(created_at)
ORDER BY date DESC;
```

### Threat distribution by client type
```sql
SELECT
    client_ip_source,
    threat_type,
    COUNT(*) as count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 2) as percentage
FROM logs
GROUP BY client_ip_source, threat_type
ORDER BY client_ip_source, count DESC;
```

## 🔄 Data Flow for Tailscale

```
Tailscale Client (Internal IP: 100.115.217.37)
    ↓
Request attack with headers:
  - X-Public-IP: 203.0.113.42
  - User-Agent: curl/8.4.0
    ↓
WAF Detector
  ├─ checkValue() → ipextract.ExtractClientIPFromHeaders()
  ├─ Priority 1: X-Public-IP → "x-public-ip"
  ├─ Mark: ip_vpn_report = true
  ├─ Detect threat (e.g., XSS)
  └─ Send event with metadata
    ↓
API Event Handler
  ├─ Extract IP (again, for API level)
  ├─ Priority 1: X-Public-IP → "x-public-ip"
  ├─ Create Log record with:
  │   - client_ip: 100.115.217.37 (RemoteAddr at API)
  │   - client_ip_vpn_report: true
  │   - client_ip_source: "x-public-ip"
  │   - client_ip_public: "203.0.113.42" ← IMPORTANT: Save the public IP!
  └─ Trigger TI enrichment
    ↓
TI Service
  ├─ Detect: isReserved(100.115.217.37) = true
  ├─ Detect: isTailscaleVPN = true (from Log.ClientIPVPNReport flag)
  ├─ Geolocate: client_ip_public = "203.0.113.42" ← Use this IP!
  ├─ Query ip-api.com for public IP:
  │   ├─ country: "IT"
  │   ├─ isp: "Vodafone Italia"
  │   └─ asn: "AS3352"
  ├─ Query AlienVault OTX for public IP reputation
  │   ├─ reputation: 15 (low risk)
  │   └─ isMalicious: false
  ├─ Set: country = "IT" (actual country!)
  ├─ Set: isp = "Vodafone Italia" (actual ISP!)
  ├─ Set: threat_source = "ip-api.com (Tailscale public IP)"
  └─ Set: threat_level = "low"
    ↓
Database (Updated Log Record)
  ├─ client_ip: 100.115.217.37
  ├─ client_ip_public: 203.0.113.42 ← Stored for reference
  ├─ client_ip_vpn_report: true
  ├─ country: IT ← Real country from geolocation
  ├─ isp: Vodafone Italia ← Real ISP from geolocation
  ├─ threat_source: ip-api.com (Tailscale public IP)
  ├─ threat_level: low ← Still low-risk due to VPN encryption
  ├─ ip_reputation: 15 ← Reputation of public IP
  └─ blocklist_status: checked
    ↓
Dashboard
  └─ Display with Tailscale VPN badge
```

## 📝 Summary

| Aspect | Detail |
|--------|--------|
| **Detection** | X-Public-IP header + reserved IP range |
| **Public IP Geolocation** | YES - We geolocate the reported public IP via ip-api.com |
| **Display** | Country=Real Country (e.g., "IT"), ISP=Real ISP (e.g., "Vodafone Italia") |
| **VPN Identification** | ClientIPVPNReport=true, ClientIPSource="x-public-ip", ClientIPPublic=stored |
| **Threat Level** | LOW (inherently safe, encrypted, even if attack from real location) |
| **Reputation** | From AlienVault OTX on the public IP |
| **Logging** | Prominent "TAILSCALE/VPN CLIENT DETECTED" with both internal & public IPs |
| **Risk** | Attack type still assessed normally |
| **Action** | Log by default (can be customized per country/ISP) |

## 🎯 Key Takeaway

Tailscale clients now show the **real country and ISP of origin** (from their public IP) while still being clearly marked as low-risk VPN traffic. This combines accurate threat intelligence with proper VPN identification, giving security analysts both the "what" (attack type/threat) and the "where" (real geographic origin) in a single, unified view.

---

**Status**: ✅ Implemented and tested (V2: Real geolocation of public IPs)
**Branch**: feature/waf-advanced-capabilities
**Latest Commits**:
- 833bcab: feat: Geolocate Tailscale/VPN client public IPs instead of internal IPs
- 5b0d7f4: fix: Improve Tailscale/VPN IP detection and logging (V1)
