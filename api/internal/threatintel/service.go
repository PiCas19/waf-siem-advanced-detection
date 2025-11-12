package threatintel

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"gorm.io/gorm"
)

const (
	// API timeouts
	httpTimeout = 5 * time.Second

	// AbuseIPDB free tier allows ~30 requests per day
	// AlienVault OTX free tier has no rate limit but is slower
	// We'll use AbuseIPDB as primary with fallback to ipapi.co for ASN/ISP
)

// EnrichmentService provides threat intelligence enrichment
type EnrichmentService struct {
	client *http.Client
	cache  map[string]*CachedEnrichment
	db     *gorm.DB
}

// CachedEnrichment stores cached threat intel data
type CachedEnrichment struct {
	Data      *ThreatIntelData
	ExpiresAt time.Time
}

// ThreatIntelData contains all enriched threat intelligence
type ThreatIntelData struct {
	IPReputation int
	IsMalicious  bool
	ASN          string
	ISP          string
	Country      string
	ThreatLevel  string
	ThreatSource string
	IsOnBlocklist bool
	BlocklistName string
	AbuseReports int
}

// NewEnrichmentService creates a new threat intelligence service
func NewEnrichmentService() *EnrichmentService {
	return &EnrichmentService{
		client: &http.Client{
			Timeout: httpTimeout,
		},
		cache: make(map[string]*CachedEnrichment),
	}
}

// SetDB sets the database connection for blocklist checking
func (es *EnrichmentService) SetDB(db *gorm.DB) {
	es.db = db
}

// EnrichLog enriches a Log entry with threat intelligence data
func (es *EnrichmentService) EnrichLog(log *models.Log) error {
	isPrivate := isPrivateIP(log.ClientIP)

	if isPrivate {
		fmt.Printf("[INFO] Private IP detected: %s - will enrich with geolocation only (no abuse score)\n", log.ClientIP)
	}

	// Check cache first
	if cached, exists := es.cache[log.ClientIP]; exists && time.Now().Before(cached.ExpiresAt) {
		fmt.Printf("[INFO] Using cached TI data for IP %s (expires in %v)\n", log.ClientIP, time.Until(cached.ExpiresAt))
		applyThreatIntel(log, cached.Data)
		return nil
	}

	fmt.Printf("[INFO] Fetching fresh TI data for IP %s\n", log.ClientIP)

	// Enrich from multiple sources
	data := &ThreatIntelData{}

	// 1. Try AbuseIPDB only for public IPs (primary source for IP reputation)
	if !isPrivate {
		fmt.Printf("[INFO] Querying AbuseIPDB for public IP %s\n", log.ClientIP)
		abuseData, err := es.checkAbuseIPDB(log.ClientIP)
		if err == nil && abuseData != nil {
			fmt.Printf("[INFO] AbuseIPDB success for IP %s: reputation=%d, isMalicious=%v, reports=%d, threatLevel=%s\n",
				log.ClientIP, abuseData.IPReputation, abuseData.IsMalicious, abuseData.AbuseReports, abuseData.ThreatLevel)
			data = abuseData
			// Also get geolocation from ipapi.co as fallback for missing fields
			if data.Country == "" {
				fmt.Printf("[INFO] AbuseIPDB missing Country, fetching from ipapi.co\n")
				apiData, _ := es.checkIPAPI(log.ClientIP)
				if apiData != nil && apiData.Country != "" {
					data.Country = apiData.Country
				}
			}
		} else {
			if err != nil {
				fmt.Printf("[WARN] AbuseIPDB failed for IP %s: %v - attempting fallback\n", log.ClientIP, err)
			} else {
				fmt.Printf("[WARN] AbuseIPDB returned nil data for IP %s - attempting fallback\n", log.ClientIP)
			}

			// 2. Fallback to ipapi.co for basic geolocation and ASN
			fmt.Printf("[INFO] Querying ipapi.co (fallback) for IP %s\n", log.ClientIP)
			apiData, err := es.checkIPAPI(log.ClientIP)
			if err == nil && apiData != nil {
				fmt.Printf("[INFO] ipapi.co success for IP %s: ASN=%s, ISP=%s, Country=%s\n",
					log.ClientIP, apiData.ASN, apiData.ISP, apiData.Country)

				// If we got data from AbuseIPDB, merge it with ipapi.co data
				if data.IPReputation > 0 {
					// Already have reputation from AbuseIPDB
					if data.Country == "" {
						data.Country = apiData.Country
					}
					if data.ASN == "" {
						data.ASN = apiData.ASN
					}
					if data.ISP == "" {
						data.ISP = apiData.ISP
					}
				} else {
					// Use all ipapi.co data
					data.ASN = apiData.ASN
					data.ISP = apiData.ISP
					data.Country = apiData.Country
					data.ThreatSource = "ipapi.co"
				}
			} else {
				if err != nil {
					fmt.Printf("[WARN] ipapi.co failed for IP %s: %v\n", log.ClientIP, err)
				} else {
					fmt.Printf("[WARN] ipapi.co returned nil data for IP %s\n", log.ClientIP)
				}
				fmt.Printf("[WARN] All TI sources failed for IP %s - no enrichment data available\n", log.ClientIP)
			}
		}
	} else {
		// For private IPs, only query ipapi.co for geolocation (won't work, but we'll set defaults)
		fmt.Printf("[INFO] Querying ipapi.co for private IP geolocation %s\n", log.ClientIP)
		apiData, err := es.checkIPAPI(log.ClientIP)
		if err == nil && apiData != nil {
			fmt.Printf("[INFO] ipapi.co success for private IP %s: ASN=%s, ISP=%s, Country=%s\n",
				log.ClientIP, apiData.ASN, apiData.ISP, apiData.Country)
			data.ASN = apiData.ASN
			data.ISP = apiData.ISP
			data.Country = apiData.Country
			data.ThreatSource = "ipapi.co"
		} else {
			// For private IPs that don't resolve, set sensible defaults
			fmt.Printf("[WARN] Could not geolocate private IP %s via ipapi.co - setting as internal/private\n", log.ClientIP)
			data.Country = "PRIVATE"
			data.ISP = "Internal/Private Network"
			data.ThreatSource = "internal"
			// Don't set reputation or malicious flag for private IPs
			data.ThreatLevel = "low" // Private networks are inherently lower risk unless configured otherwise
		}
	}

	// Check blocklist if database is available
	if es.db != nil {
		fmt.Printf("[INFO] Checking blocklist for IP %s with threat %s\n", log.ClientIP, log.ThreatType)
		var blockedIP models.BlockedIP
		now := time.Now()

		// Check if IP is blocked for this specific threat or globally
		err := es.db.Where("ip_address = ? AND (description = ? OR description = ?) AND (permanent = ? OR expires_at > ?)",
			log.ClientIP, log.ThreatType, "GLOBAL", true, now).First(&blockedIP).Error

		if err == nil {
			data.IsOnBlocklist = true
			data.BlocklistName = blockedIP.Description
			fmt.Printf("[INFO] IP %s is blocked: %s (expires: %v, permanent: %v)\n",
				log.ClientIP, blockedIP.Description, blockedIP.ExpiresAt, blockedIP.Permanent)
		} else if err != gorm.ErrRecordNotFound {
			fmt.Printf("[WARN] Error checking blocklist for IP %s: %v\n", log.ClientIP, err)
		} else {
			fmt.Printf("[INFO] IP %s is not on blocklist\n", log.ClientIP)
		}
	} else {
		fmt.Printf("[WARN] Database not initialized in enrichment service - cannot check blocklist\n")
	}

	// Cache the result (24 hour cache)
	es.cache[log.ClientIP] = &CachedEnrichment{
		Data:      data,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	fmt.Printf("[INFO] Cached TI data for IP %s (24h TTL)\n", log.ClientIP)

	// Apply enrichment to log
	applyThreatIntel(log, data)

	return nil
}

// checkAbuseIPDB queries AbuseIPDB for IP reputation
// Free tier: ~30 requests per day, no API key needed for basic lookups
func (es *EnrichmentService) checkAbuseIPDB(ip string) (*ThreatIntelData, error) {
	// AbuseIPDB free API endpoint (no auth required for basic lookups)
	url := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90", ip)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	// AbuseIPDB recommends User-Agent
	req.Header.Set("User-Agent", "WAF-SIEM-ThreatIntel/1.0")

	resp, err := es.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("abuseipdb request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("abuseipdb returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse AbuseIPDB response
	var abuseResp struct {
		Data struct {
			AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
			CountryCode          string `json:"countryCode"`
			UsageType            string `json:"usageType"`
			TotalReports         int    `json:"totalReports"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &abuseResp); err != nil {
		return nil, fmt.Errorf("failed to parse abuseipdb response: %w", err)
	}

	data := &ThreatIntelData{
		IPReputation: abuseResp.Data.AbuseConfidenceScore,
		IsMalicious:  abuseResp.Data.AbuseConfidenceScore > 25,
		Country:      abuseResp.Data.CountryCode,
		AbuseReports: abuseResp.Data.TotalReports,
		ThreatSource: "abuseipdb",
		ThreatLevel:  calculateThreatLevel(abuseResp.Data.AbuseConfidenceScore),
	}

	return data, nil
}

// checkIPAPI queries ipapi.co for geolocation and ASN info
// Free tier: 30,000 requests/month, no API key required
func (es *EnrichmentService) checkIPAPI(ip string) (*ThreatIntelData, error) {
	url := fmt.Sprintf("https://ipapi.co/%s/json/", ip)

	resp, err := es.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("ipapi request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ipapi returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var apiResp struct {
		Org     string `json:"org"`
		Country string `json:"country_code"`
		ISP     string `json:"isp"`
	}

	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse ipapi response: %w", err)
	}

	data := &ThreatIntelData{
		ASN:          parseASN(apiResp.Org),
		ISP:          apiResp.ISP,
		Country:      apiResp.Country,
		ThreatSource: "ipapi.co",
	}

	return data, nil
}

// isPrivateIP checks if an IP address is private/internal
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true
	}

	return ip.IsPrivate() || ip.IsLoopback()
}

// parseASN extracts ASN from organization string (e.g., "AS12345 Company Name")
func parseASN(org string) string {
	if len(org) < 2 {
		return ""
	}

	// Check if it starts with AS
	if org[0:2] == "AS" {
		// Extract the number part
		for i, ch := range org {
			if ch < '0' || ch > '9' {
				if i > 2 { // Found the end of the number
					return org[0:i]
				}
				break
			}
		}
	}
	return org
}

// calculateThreatLevel determines threat level based on abuse confidence score
func calculateThreatLevel(score int) string {
	switch {
	case score >= 75:
		return "critical"
	case score >= 50:
		return "high"
	case score >= 25:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "none"
	}
}

// applyThreatIntel applies enriched threat data to a log entry
func applyThreatIntel(log *models.Log, data *ThreatIntelData) {
	if data == nil {
		return
	}

	now := time.Now()
	log.EnrichedAt = &now

	if data.IPReputation > 0 {
		log.IPReputation = &data.IPReputation
	}
	if data.IsMalicious {
		log.IsMalicious = true
	}
	if data.ASN != "" {
		log.ASN = data.ASN
	}
	if data.ISP != "" {
		log.ISP = data.ISP
	}
	if data.Country != "" {
		log.Country = data.Country
	}
	if data.ThreatLevel != "" {
		log.ThreatLevel = data.ThreatLevel
	}
	if data.ThreatSource != "" {
		log.ThreatSource = data.ThreatSource
	}
	if data.IsOnBlocklist {
		log.IsOnBlocklist = true
		log.BlocklistName = data.BlocklistName
	}
	if data.AbuseReports > 0 {
		log.AbuseReports = &data.AbuseReports
	}
}
