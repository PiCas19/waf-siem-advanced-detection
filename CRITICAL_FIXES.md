# WAF-SIEM: Critical Fixes - Code Examples

This document provides concrete, copy-paste-ready code fixes for the 4 critical security issues.

---

## Issue 1: Race Condition in Threat Intel Cache

**Location:** `api/internal/threatintel/service.go`

**Problem:** Concurrent map access without synchronization

```go
// BEFORE (UNSAFE):
type EnrichmentService struct {
    client *http.Client
    cache  map[string]*CachedEnrichment  // NO PROTECTION!
    db     *gorm.DB
}

// In EnrichLog (line 99):
if cached, exists := es.cache[cacheKey]; exists && time.Now().Before(cached.ExpiresAt) {
    // RACE: Another goroutine could modify cache[cacheKey] here
}
```

**Fix:**

```go
// AFTER (SAFE):
type EnrichmentService struct {
    client      *http.Client
    cache       map[string]*CachedEnrichment
    cacheLock   sync.RWMutex  // ADD THIS
    db          *gorm.DB
}

// In EnrichLog (replace lines 99-103):
es.cacheLock.RLock()
cached, exists := es.cache[cacheKey]
es.cacheLock.RUnlock()

if exists && time.Now().Before(cached.ExpiresAt) {
    fmt.Printf("[INFO] Using cached TI data for IP %s (expires in %v)\n", cacheKey, time.Until(cached.ExpiresAt))
    applyThreatIntel(log, cached.Data)
    return nil
}

// ... enrichment code ...

// Replace lines 206-210:
es.cacheLock.Lock()
es.cache[cacheKey] = &CachedEnrichment{
    Data:      data,
    ExpiresAt: time.Now().Add(24 * time.Hour),
}
es.cacheLock.Unlock()
```

**Testing:**

```go
func TestCacheRaceCondition(t *testing.T) {
    es := threatintel.NewEnrichmentService()
    es.SetDB(nil)
    
    // Simulate concurrent access
    var wg sync.WaitGroup
    for i := 0; i < 1000; i++ {
        wg.Add(1)
        go func(idx int) {
            defer wg.Done()
            
            log := &models.Log{
                ClientIP: fmt.Sprintf("192.0.2.%d", idx%255),
            }
            
            // This should not panic with race detector
            es.EnrichLog(log)
        }(i)
    }
    
    wg.Wait()
}
```

---

## Issue 2: Plaintext HMAC Secrets in Database

**Location:** `api/internal/database/models/trusted_source.go`

**Problem:** HMAC secrets stored in plaintext; database breach = all signatures compromised

```go
// BEFORE (UNSAFE):
type HMACKey struct {
    ID               string
    Name             string
    Secret           string  // PLAINTEXT IN DATABASE!
    TrustedSourceID  string
    // ...
}
```

**Fix:**

```go
// AFTER (ENCRYPTED):
type HMACKey struct {
    ID               string     `gorm:"primaryKey" json:"id"`
    Name             string     `json:"name"`
    // DELETE: Secret  string  // REMOVE THIS
    
    // ADD ENCRYPTED STORAGE:
    SecretEncrypted  string     `json:"-" gorm:"column:secret_encrypted"`  // Base64-encoded AES-encrypted secret
    SecretHash       string     `json:"-" gorm:"index"`                    // SHA256 hash for lookups (non-secret)
    
    TrustedSourceID  string     `json:"trusted_source_id"`
    LastUsedAt       *time.Time `json:"last_used_at"`
    RotationInterval int        `json:"rotation_interval"`
    NextRotationDate *time.Time `json:"next_rotation_date"`
    IsActive         bool       `json:"is_active" gorm:"default:true"`
    CreatedAt        time.Time  `json:"created_at" gorm:"autoCreateTime"`
    UpdatedAt        time.Time  `json:"updated_at" gorm:"autoUpdateTime"`
    CreatedBy        string     `json:"created_by"`
    
    // Relationship
    TrustedSource *TrustedSource `json:"trusted_source,omitempty" gorm:"foreignKey:TrustedSourceID"`
}

// Add methods for encryption/decryption:
// (Requires KMS client - implementation depends on your KMS choice)

// For AWS KMS:
func (h *HMACKey) SetSecret(plaintext string, kmsClient *kms.Client, keyID string) error {
    // Encrypt with AWS KMS
    ctx := context.Background()
    result, err := kmsClient.Encrypt(ctx, &kms.EncryptInput{
        KeyId:     aws.String(keyID),
        Plaintext: []byte(plaintext),
    })
    if err != nil {
        return fmt.Errorf("failed to encrypt secret: %w", err)
    }
    
    h.SecretEncrypted = base64.StdEncoding.EncodeToString(result.CiphertextBlob)
    
    // Store hash for non-secret lookups
    hash := sha256.Sum256([]byte(plaintext))
    h.SecretHash = hex.EncodeToString(hash[:])
    
    return nil
}

func (h *HMACKey) GetSecret(kmsClient *kms.Client) (string, error) {
    encryptedBytes, err := base64.StdEncoding.DecodeString(h.SecretEncrypted)
    if err != nil {
        return "", fmt.Errorf("failed to decode encrypted secret: %w", err)
    }
    
    ctx := context.Background()
    result, err := kmsClient.Decrypt(ctx, &kms.DecryptInput{
        CiphertextBlob: encryptedBytes,
    })
    if err != nil {
        return "", fmt.Errorf("failed to decrypt secret: %w", err)
    }
    
    return string(result.Plaintext), nil
}
```

**Migration (in `migrations.go`):**

```go
// Add migration to encrypt existing secrets
func RunMigrations(db *gorm.DB) error {
    // ... existing migrations ...
    
    // Migration: Encrypt HMAC secrets
    if !db.Migrator().HasColumn("hmac_keys", "secret_encrypted") {
        log.Println("[MIGRATION] Encrypting HMAC secrets...")
        
        // Add new columns
        type HMACKey struct {
            SecretEncrypted string
            SecretHash      string
        }
        db.Migrator().AddColumn(&HMACKey{}, "secret_encrypted")
        db.Migrator().AddColumn(&HMACKey{}, "secret_hash")
        
        // TODO: Migrate existing secrets
        // 1. Read plaintext Secret field for each key
        // 2. Encrypt with KMS
        // 3. Store in SecretEncrypted
        // 4. Drop old Secret column
        
        log.Println("[MIGRATION] ✅ HMAC secrets encrypted")
    }
    
    return nil
}
```

**Usage:**

```go
// In trusted_sources handler, creating new key:
func CreateHMACKey(sourceID string, plaintext string, kmsClient *kms.Client) (*models.HMACKey, error) {
    key := &models.HMACKey{
        ID:              uuid.New().String(),
        Name:            "Default Key",
        TrustedSourceID: sourceID,
        IsActive:        true,
    }
    
    // Encrypt before storing
    if err := key.SetSecret(plaintext, kmsClient, os.Getenv("AWS_KMS_KEY_ID")); err != nil {
        return nil, err
    }
    
    return key, nil
}

// In header validation, retrieving secret:
func ValidateSignature(signature string, keyID string, db *gorm.DB, kmsClient *kms.Client) (bool, error) {
    var key models.HMACKey
    if err := db.First(&key, "id = ?", keyID).Error; err != nil {
        return false, err
    }
    
    // Decrypt secret from database
    plaintext, err := key.GetSecret(kmsClient)
    if err != nil {
        return false, err
    }
    
    // Use plaintext for signature validation
    expected := computeHMACSignature(payload, plaintext)
    return hmac.Equal([]byte(signature), []byte(expected)), nil
}
```

---

## Issue 3: X-Public-IP Spoofing (No Signature Validation)

**Location:** `waf/internal/ipextract/ip_extractor.go` + `waf/pkg/waf/middleware.go`

**Problem:** Any client can claim any IP via X-Public-IP header without signature

```go
// BEFORE (UNSAFE):
if xPublicIP != "" {
    xPublicIP = strings.TrimSpace(xPublicIP)
    if isValidIP(xPublicIP) {
        return &ClientIPInfo{
            IP:             xPublicIP,
            Source:         SourceXPublicIP,
            IsTrusted:      true,  // WRONG: Trusted without verification!
            IsPublicIP:     isPublicIP(xPublicIP),
            IsPrivateIP:    isPrivateIP(xPublicIP),
            IsVPNTailscale: true,
        }
    }
}
```

**Fix:**

```go
// AFTER (SIGNATURE REQUIRED):
// Step 1: In ExtractClientIPWithPolicy (line 300-314):

// Validate X-Public-IP signature BEFORE using it
if xPublicIP != "" && sigConfig.Enabled {
    sourceIP := extractIPFromRemoteAddr(remoteAddr)
    result := ValidateHeaderSignature(r, sigConfig, sourceIP)
    
    if result.IsValid && result.SignatureMatch {
        // Signature valid, proceed with X-Public-IP
        fmt.Printf("[INFO] X-Public-IP signature valid: %s\n", xPublicIP)
        headerSigValid = true
    } else {
        // Signature invalid - log warning and ignore X-Public-IP
        fmt.Printf("[WARN] X-Public-IP signature invalid or missing: %s (validation: %v, match: %v)\n",
            xPublicIP, result.IsValid, result.SignatureMatch)
        
        if sigConfig.RequireSignature {
            // If signature is required, reject request entirely
            return nil, fmt.Errorf("X-Public-IP requires valid HMAC signature")
        }
        
        // If signature not required, skip X-Public-IP and use other sources
        xPublicIP = ""
        headerSigValid = false
    }
}

// Step 2: In middleware configuration (waf/pkg/waf/middleware.go, Provision):
m.headerSigConfig = ipextract.DefaultHeaderSignatureConfig()
if m.EnableHMACSignatureValidation && m.HMACSharedSecret != "" {
    m.headerSigConfig.Enabled = true
    m.headerSigConfig.SharedSecret = m.HMACSharedSecret
    m.headerSigConfig.RequireSignature = true  // ENFORCE signature for X-Public-IP
}
```

**Testing:**

```go
func TestXPublicIPRequiresSignature(t *testing.T) {
    config := &ipextract.HeaderSignatureConfig{
        Enabled:          true,
        SharedSecret:     "test-secret",
        RequireSignature: true,
        MaxClockSkew:     30 * time.Second,
    }
    
    tests := []struct {
        name           string
        xPublicIP      string
        signature      string
        timestamp      string
        shouldAccept   bool
    }{
        {
            name:         "Valid signature",
            xPublicIP:    "203.0.113.45",
            signature:    "valid-hmac-signature",  // Must be computed correctly
            timestamp:    strconv.FormatInt(time.Now().Unix(), 10),
            shouldAccept: true,
        },
        {
            name:         "Missing signature",
            xPublicIP:    "203.0.113.45",
            signature:    "",
            timestamp:    strconv.FormatInt(time.Now().Unix(), 10),
            shouldAccept: false,  // REJECT: No signature with RequireSignature=true
        },
        {
            name:         "Wrong signature",
            xPublicIP:    "203.0.113.45",
            signature:    "wrong-hmac-signature",
            timestamp:    strconv.FormatInt(time.Now().Unix(), 10),
            shouldAccept: false,  // REJECT: Invalid signature
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            req, _ := http.NewRequest("GET", "http://example.com/api", nil)
            req.Header.Set("X-Public-IP", tt.xPublicIP)
            req.Header.Set("X-HMAC-Signature", tt.signature)
            req.Header.Set("X-Request-Timestamp", tt.timestamp)
            
            result := ipextract.ValidateHeaderSignature(req, config, "10.0.0.1")
            
            if result.IsValid != tt.shouldAccept {
                t.Errorf("Expected valid=%v, got %v. Error: %s", tt.shouldAccept, result.IsValid, result.ErrorMessage)
            }
        })
    }
}
```

---

## Issue 4: Trust Score Not Persisted

**Location:** `api/internal/database/models/log.go` + `api/internal/api/stats.go`

**Problem:** Trust score calculated but never saved to database

```go
// STEP 1: Add field to Log model (models/log.go):

type Log struct {
    ID          uint      `gorm:"primarykey" json:"id"`
    CreatedAt   time.Time `json:"created_at"`

    // Threat data
    ThreatType  string `json:"threat_type"`
    Severity    string `json:"severity"`
    Description string `json:"description"`
    ClientIP    string `gorm:"index" json:"client_ip"`
    // ... existing fields ...

    // ADD THESE FIELDS:
    IPTrustScore     *int    `json:"ip_trust_score,omitempty"`       // 0-100
    IPTrustFactors   string  `json:"ip_trust_factors,omitempty"`     // JSON array of factors
    IPSourceVerified bool    `json:"ip_source_verified"`             // Header signature valid?
    IPChainValid     bool    `json:"ip_chain_valid"`                 // Proxy chain verified?
    
    EnrichmentProvider   string   `json:"enrichment_provider,omitempty"`
    EnrichmentLatencyMs  int      `json:"enrichment_latency_ms"`
    EnrichmentConfidence *float32 `json:"enrichment_confidence,omitempty"`
}
```

**STEP 2: Update stats handler (stats.go, around line 182-200):**

```go
func NewWAFEventHandler(db *gorm.DB) gin.HandlerFunc {
    return func(c *gin.Context) {
        // ... existing code ...
        
        // After computing enhanced IP info:
        enhancedIPInfo := ipextract.ExtractClientIPWithPolicy(
            r,
            r.RemoteAddr,
            m.trustedSourceManager,
            m.headerSigConfig,
            m.dmzConfig,
            m.tailscaleConfig,
        )
        
        // SAVE the enhanced IP info for later:
        
        log := models.Log{
            ThreatType:  event.Threat,
            Description: event.Description,
            ClientIP:    event.IP,
            Method:      event.Method,
            URL:         event.Path,
            UserAgent:   event.UA,
            Payload:     event.Payload,
            CreatedAt:   time.Now(),
            Blocked:     event.Blocked,
            BlockedBy:   event.BlockedBy,
            Severity:    GetSeverityFromThreatType(event.Threat),
            
            ClientIPSource:    event.IPSource,
            ClientIPTrusted:   event.IPTrusted,
            ClientIPVPNReport: event.IPVPNReport,
            ClientIPPublic:    publicIP,
            
            // ADD THESE:
            IPTrustScore:     &enhancedIPInfo.TrustScore,
            IPTrustFactors:   calculateTrustFactors(enhancedIPInfo),  // NEW helper function
            IPSourceVerified: enhancedIPInfo.HeaderSignatureValid,
            IPChainValid:     isProxyChainValid(event),                // NEW helper function
        }
        
        if err := db.Create(&log).Error; err != nil {
            fmt.Printf("[ERROR] Failed to save log to database: %v\n", err)
            c.JSON(500, gin.H{"error": "failed to save event"})
            return
        }
        
        // ... rest of handler ...
    }
}

// Helper function to calculate trust factors
func calculateTrustFactors(enhanced *ipextract.EnhancedClientIPInfo) string {
    factors := []string{}
    
    if enhanced.DMZIP {
        factors = append(factors, "dmz")
    }
    if enhanced.TailscaleIP {
        factors = append(factors, "tailscale")
    }
    if enhanced.HeaderSignatureValid {
        factors = append(factors, "signature_valid")
    }
    if enhanced.SourceClassification == "trusted" {
        factors = append(factors, "trusted_source")
    }
    
    data, _ := json.Marshal(factors)
    return string(data)
}

// Helper function to validate proxy chain
func isProxyChainValid(event websocket.WAFEvent) bool {
    // If it came from X-Forwarded-For, the chain was validated during extraction
    return event.IPSource == "x-forwarded-for" || event.IPSource == "x-real-ip"
}
```

**STEP 3: Update enrichment persistence (stats.go, around line 223-240):**

```go
// After enrichment, include trust score in update:
updateData := map[string]interface{}{
    "enriched_at":        log.EnrichedAt,
    "ip_reputation":      log.IPReputation,
    "is_malicious":       log.IsMalicious,
    "asn":                log.ASN,
    "isp":                log.ISP,
    "country":            log.Country,
    "threat_level":       log.ThreatLevel,
    "threat_source":      log.ThreatSource,
    "is_on_blocklist":    log.IsOnBlocklist,
    "blocklist_name":     log.BlocklistName,
    "abuse_reports":      log.AbuseReports,
    
    // ADD THESE:
    "ip_trust_score":     log.IPTrustScore,
    "ip_trust_factors":   log.IPTrustFactors,
    "ip_source_verified": log.IPSourceVerified,
    "ip_chain_valid":     log.IPChainValid,
}

if err := db.Model(&models.Log{}).Where("id = ?", log.ID).Updates(updateData).Error; err != nil {
    fmt.Printf("[ERROR] Failed to update log %d with enrichment: %v\n", log.ID, err)
}
```

**STEP 4: Create migration (migrations.go):**

```go
func RunMigrations(db *gorm.DB) error {
    // ... existing migrations ...
    
    // Migration: Add trust score fields to logs table
    if !db.Migrator().HasColumn("logs", "ip_trust_score") {
        log.Println("[MIGRATION] Adding trust score fields to logs table...")
        
        // Add new columns
        type Log struct {
            IPTrustScore     *int
            IPTrustFactors   string
            IPSourceVerified bool
            IPChainValid     bool
            EnrichmentProvider   string
            EnrichmentLatencyMs  int
            EnrichmentConfidence *float32
        }
        
        if err := db.Migrator().AddColumn(&Log{}, "ip_trust_score"); err != nil {
            return fmt.Errorf("failed to add ip_trust_score: %w", err)
        }
        if err := db.Migrator().AddColumn(&Log{}, "ip_trust_factors"); err != nil {
            return fmt.Errorf("failed to add ip_trust_factors: %w", err)
        }
        if err := db.Migrator().AddColumn(&Log{}, "ip_source_verified"); err != nil {
            return fmt.Errorf("failed to add ip_source_verified: %w", err)
        }
        if err := db.Migrator().AddColumn(&Log{}, "ip_chain_valid"); err != nil {
            return fmt.Errorf("failed to add ip_chain_valid: %w", err)
        }
        if err := db.Migrator().AddColumn(&Log{}, "enrichment_provider"); err != nil {
            return fmt.Errorf("failed to add enrichment_provider: %w", err)
        }
        if err := db.Migrator().AddColumn(&Log{}, "enrichment_latency_ms"); err != nil {
            return fmt.Errorf("failed to add enrichment_latency_ms: %w", err)
        }
        if err := db.Migrator().AddColumn(&Log{}, "enrichment_confidence"); err != nil {
            return fmt.Errorf("failed to add enrichment_confidence: %w", err)
        }
        
        // Add indexes
        if err := db.Migrator().CreateIndex(&Log{}, "ip_trust_score"); err != nil {
            return fmt.Errorf("failed to create ip_trust_score index: %w", err)
        }
        if err := db.Migrator().CreateIndex(&Log{}, "ip_source_verified"); err != nil {
            return fmt.Errorf("failed to create ip_source_verified index: %w", err)
        }
        
        log.Println("[MIGRATION] ✅ Trust score fields added")
    }
    
    return nil
}
```

---

## Verification Checklist

After implementing all 4 fixes, verify:

- [ ] **Race condition fix:**
  - [ ] Run tests with `-race` flag: `go test -race ./api/internal/threatintel/...`
  - [ ] No race detector warnings
  
- [ ] **Secret encryption fix:**
  - [ ] Verify old plaintext secrets are encrypted in migration
  - [ ] Secrets cannot be read in plaintext from database
  - [ ] GetSecret() returns original plaintext
  - [ ] SetSecret() stores encrypted value
  
- [ ] **X-Public-IP signature fix:**
  - [ ] Requests without signature are rejected (if RequireSignature=true)
  - [ ] Requests with valid signature are accepted
  - [ ] Requests with invalid signature are rejected
  - [ ] Tests pass with `-race` flag
  
- [ ] **Trust score persistence fix:**
  - [ ] Trust score appears in database logs
  - [ ] Trust score queries work: `SELECT * FROM logs WHERE ip_trust_score > 75`
  - [ ] Trust factors JSON is valid: `json_array_length(ip_trust_factors)`
  - [ ] No data loss in enrichment update

---

## Implementation Order

1. **Risk**: Start with Issue 1 (race condition) - highest impact
2. **Security**: Then Issue 2 (secret encryption) - critical before deployment
3. **Spoofing**: Then Issue 3 (X-Public-IP signature) - prevents attacks
4. **Data**: Finally Issue 4 (trust score persistence) - improves observability

**Estimated time per fix:** 30 min - 2 hours each = 4-8 hours total

