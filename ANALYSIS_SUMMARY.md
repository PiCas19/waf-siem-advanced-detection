# WAF-SIEM Analysis: Executive Summary

**Full Analysis:** See `WAF_SIEM_ANALYSIS.md` (1483 lines)

## Quick Reference: Critical Issues

### 1. CRITICAL SECURITY ISSUES (Fix Immediately)

| Issue | Location | Severity | Action |
|-------|----------|----------|--------|
| **Race condition in cache** | `threatintel/service.go:27` | CRITICAL | Add `sync.RWMutex` |
| **Plaintext HMAC secrets** | `models/trusted_source.go:28` | CRITICAL | Encrypt with KMS |
| **X-Public-IP spoofing** | `ip_extractor.go:126-139` | CRITICAL | Require signature validation |
| **Trust score not persisted** | `stats.go:236-240` | HIGH | Add to database update |

### 2. HIGH-PRIORITY PERFORMANCE ISSUES (Fix This Sprint)

| Issue | Location | Impact | Action |
|-------|----------|--------|--------|
| **Blocking enrichment** | `stats.go:215` | 5s+ latency | Move to async worker |
| **CIDR parsed per request** | `ip_extractor.go:264-268` | ~500μs/req | Pre-compile ranges |
| **No cache mutex** | `threatintel/service.go:57` | Race condition | Add thread safety |
| **Tailscale inconsistency** | `threatintel/service.go:68-96` | Data quality | Add validation |

### 3. MEDIUM PRIORITY (Next Sprint)

| Issue | Location | Action |
|-------|----------|--------|
| **Duplicate IP extraction** | `stats.go:53-105` | Create single shared function |
| **No validation logs** | `models/trusted_source.go:77-98` | Populate during validation |
| **Thread-unsafe error count** | `models/trusted_source.go:34` | Add sync.RWMutex |
| **Cache key collision** | `threatintel/service.go:93-96` | Use compound key |
| **Race condition in log update** | `stats.go:207-240` | Use transaction |

---

## Trust Score Analysis

**Current State:** Static 7-factor system, 0-100 scale

**Score Calculation** (header_validator.go:291-346):
- Base: 50 (neutral)
- +20: Public IP from remote
- +15: Trusted proxy headers
- +20: Tailscale + valid signature
- +10: DMZ sources
- +10: Whitelisted
- -15: X-Public-IP without signature
- -20: Private IP in public header

**Critical Limitation:** Score calculated but never saved to database

**Improvement Suggestions:**
1. Add time-decay function (exponential decay)
2. Implement behavioral baselines (request frequency, user-agent)
3. Integrate ASN reputation scoring
4. Add geolocation velocity detection (impossible travel)
5. Validate full X-Forwarded-For chain
6. Use score in graduated response (block < 25, CAPTCHA 25-50, monitor 50-75, allow 75+)

---

## IP Reputation & Caching Analysis

**Current State:** In-memory cache, 24-hour TTL, NO thread protection

**Data Sources:**
- **ip-api.com**: Geolocation, ASN, ISP (45 req/min free)
- **AlienVault OTX**: Reputation score, threat count (unlimited free)
- **Local blocklist**: Database check

**Critical Issues:**
1. **Race condition** - No `sync.RWMutex` on cache map (line 27)
2. **Blocking latency** - 5+ seconds per new IP (synchronous API calls)
3. **Cache key collision** - Tailscale internal IP vs public IP
4. **No adaptive TTL** - Fixed 24h regardless of threat level

**Performance:**
- First-seen IP: 5000ms+ (blocking)
- Cache hit ratio: ~70% (estimated)
- API rate limit: 45 req/min (ip-api)

**Improvements:**
1. Add `sync.RWMutex cacheLock`
2. Move enrichment to async background worker
3. Use compound cache key: `"PUBLIC:IP"` and `"INTERNAL:IP"`
4. Adaptive TTL based on threat level
5. Batch API requests (5-second windows)
6. Add exponential backoff for rate limiting

---

## Database Models Analysis

### Log Model Gaps
**Missing Fields:**
- `IPTrustScore` (0-100) - calculated but never saved
- `EnrichmentProvider` - which API enriched this
- `EnrichmentConfidence` (0.0-1.0) - accuracy metric
- `EnrichmentLatencyMs` - performance tracking
- `ClientIPPublic` index - slow Tailscale lookups

**Missing Indexes:**
- `ClientIPPublic` (used by Tailscale clients)
- `IPTrustScore` (for trust-based queries)
- Composite: `(CreatedAt, IPTrusted)` (time range + trust)

### TrustedSource Model Issues
**Security Issues:**
1. HMAC secrets in plaintext (line 28)
2. GetSecretHash only shows first/last 4 chars (line 137-143)
3. No audit trail of secret usage
4. No key rotation enforcement

**Data Flow Issues:**
1. `SourceValidationLog` defined but never populated (line 77-98)
2. `CurrentErrorCount` not thread-safe (line 34)
3. Error count resets hourly but not protected by mutex

**Fix Priority:**
1. Encrypt secrets with KMS (CRITICAL)
2. Add trust_score to Log model (HIGH)
3. Move secrets to HMACKey table exclusively (HIGH)
4. Add sync.RWMutex to TrustedSource (MEDIUM)
5. Populate validation logs during checks (MEDIUM)

---

## Tailscale & Private IP Detection

**Current State:** IP priority-based extraction, post-extraction detection

**IP Extraction Order:**
1. X-Public-IP (Tailscale/VPN) - highest priority
2. X-Forwarded-For (trusted proxy)
3. X-Real-IP (trusted proxy)
4. RemoteAddr (direct connection)

**Tailscale Detection:**
- Checks if IP in 100.64.0.0/10 CIDR
- No validation of consistency
- Re-parses CIDR on every request

**Critical Issues:**
1. **X-Public-IP trusted implicitly** - no signature required
2. **Tailscale detection post-extraction** - can't change trust retroactively
3. **No consistency validation** - accepts invalid IP combinations
4. **CIDR not cached** - ~500μs overhead per request
5. **No header inconsistency detection** - can submit contradicting headers

**Example Attack:**
```
Request:
  X-Public-IP: 203.0.113.45 (arbitrary public IP!)
  X-Forwarded-For: 10.0.0.1 (private IP - ignored)
Result:
  Client IP: 203.0.113.45 (any attacker can claim any IP)
```

**Fixes:**
1. Require HMAC signature for X-Public-IP
2. Pre-compile CIDR ranges in init
3. Validate Tailscale consistency (check if internal IP actually in range)
4. Detect header contradictions
5. Validate IP consistency across all headers

---

## API Stats Handler Analysis

**Current Flow:**
1. Extract IP from headers (5 checks)
2. Create log entry (database)
3. Enrich with threat intel (5s+ blocking)
4. Update log with enrichment (database)
5. Broadcast to WebSocket

**Critical Issues:**
1. **Blocking enrichment** (line 215) - 5s latency per request
2. **Trust score not saved** (line 236-240) - calculated but lost
3. **Race condition** - Create → Enrich → Update is non-atomic
4. **Duplicate IP extraction** - same logic in multiple places
5. **No request validation** - malformed headers accepted

**Performance Bottleneck:**
```
Steps 1-2:   ~10ms (database insert)
Step 3:      5000+ms (external API calls) ← BOTTLENECK
Step 4:      ~5ms (database update)
Step 5:      <1ms (WebSocket)
Total:       5015+ms (dominated by enrichment)
```

**Improvements:**
1. **Async enrichment** - Return immediately, enrich in background
2. **Persist trust score** - Add to update query
3. **Use transactions** - Make create+update atomic
4. **Share TI service** - One instance, shared cache
5. **Add validation middleware** - Validate JSON before handler
6. **Consolidate IP extraction** - Single function used everywhere

---

## Implementation Priority

### Week 1 - Critical Security (MUST DO)
- [ ] Add `sync.RWMutex` to threat intel cache
- [ ] Encrypt HMAC secrets in database
- [ ] Require signature validation for X-Public-IP
- [ ] Add IP consistency validation for Tailscale

### Week 2 - Data & Atomicity
- [ ] Add `ip_trust_score` to Log model
- [ ] Use transactions for log creation+enrichment+update
- [ ] Populate validation logs during scoring
- [ ] Add thread safety to error count tracking

### Week 3 - Performance
- [ ] Move enrichment to async worker
- [ ] Pre-compile CIDR ranges
- [ ] Implement adaptive cache TTL
- [ ] Batch API requests to external providers

### Week 4 - Advanced Features
- [ ] Geolocation velocity detection
- [ ] ASN reputation scoring
- [ ] Behavioral anomaly detection
- [ ] Graduated response scaling

---

## Code Locations Reference

### Trust Score
- Calculate: `waf/internal/ipextract/header_validator.go:291-346`
- Send to API: `waf/pkg/waf/middleware.go:748`
- Store: Missing from `api/internal/api/stats.go:236-240`

### IP Reputation
- Fetch: `api/internal/threatintel/service.go:67-216`
- Cache: `api/internal/threatintel/service.go:27, 206-210`
- Apply: `api/internal/threatintel/service.go:463-500`

### Database Models
- Log: `api/internal/database/models/log.go:1-40`
- TrustedSource: `api/internal/database/models/trusted_source.go:1-144`
- Migrations: `api/internal/database/migrations.go:1-35`

### IP Detection
- Extract: `waf/internal/ipextract/ip_extractor.go:113-216`
- Tailscale: `waf/internal/ipextract/ip_extractor.go:255-267`
- Validate: `waf/internal/ipextract/header_validator.go:56-157`

### API Handling
- Handler: `api/internal/api/stats.go:136-246`
- Enrichment: `api/internal/api/stats.go:213-240`
- Extraction: `api/internal/api/stats.go:45-105`

---

## Testing Checklist

- [ ] Unit tests for trust score with edge cases
- [ ] Concurrency tests for cache (1000+ goroutines)
- [ ] Integration tests for enrichment pipeline
- [ ] Security tests for IP spoofing scenarios
- [ ] Performance benchmarks (before/after optimization)
- [ ] Tailscale consistency validation tests
- [ ] Transaction atomicity tests for log updates

---

**Total Analysis Size:** 1483 lines  
**Issues Found:** 15+ major issues across 5 components  
**Estimated Fix Time:** 3-4 weeks (all priorities)  
**Recommended Starting Point:** Critical security issues (Week 1)
