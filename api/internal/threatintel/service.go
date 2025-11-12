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

	// 1. Query IP-API for geolocation and basic info for all IPs (public and private)
	if !isPrivate {
		fmt.Printf("[INFO] Querying ip-api.com for public IP %s\n", log.ClientIP)
	}

	geoData, err := es.checkGeoIP(log.ClientIP)
	if err == nil && geoData != nil {
		if !isPrivate {
			fmt.Printf("[INFO] ip-api.com success for IP %s: ASN=%s, ISP=%s, Country=%s\n",
				log.ClientIP, geoData.ASN, geoData.ISP, geoData.Country)
		}
		data = geoData

		// 2. Try to enhance with reputation data from AlienVault OTX (free, no rate limits)
		if !isPrivate {
			fmt.Printf("[INFO] Querying AlienVault OTX for IP reputation %s\n", log.ClientIP)
			reputationData, err := es.checkAlienVaultOTX(log.ClientIP)
			if err == nil && reputationData != nil {
				fmt.Printf("[INFO] AlienVault OTX success for IP %s: reputation=%d, isMalicious=%v, threatLevel=%s\n",
					log.ClientIP, reputationData.IPReputation, reputationData.IsMalicious, reputationData.ThreatLevel)
				// Merge reputation data with geolocation data
				data.IPReputation = reputationData.IPReputation
				data.IsMalicious = reputationData.IsMalicious
				data.ThreatLevel = reputationData.ThreatLevel
				data.AbuseReports = reputationData.AbuseReports
				data.ThreatSource = "alienvault-otx + ip-api.com"
			} else {
				if err != nil {
					fmt.Printf("[WARN] AlienVault OTX failed for IP %s: %v - using geolocation only\n", log.ClientIP, err)
				}
				// If OTX fails, just use geolocation data
				data.ThreatSource = "ip-api.com"
			}
		}
	} else {
		// For private IPs, only query IP-API for geolocation (won't work, but we'll set defaults)
		fmt.Printf("[INFO] Querying ip-api.com for private IP geolocation %s\n", log.ClientIP)
		geoData, err := es.checkGeoIP(log.ClientIP)
		if err == nil && geoData != nil {
			fmt.Printf("[INFO] ip-api.com success for private IP %s: ASN=%s, ISP=%s, Country=%s\n",
				log.ClientIP, geoData.ASN, geoData.ISP, geoData.Country)
			data.ASN = geoData.ASN
			data.ISP = geoData.ISP
			data.Country = geoData.Country
			data.ThreatSource = "ip-api.com"
		} else {
			// For private IPs that don't resolve, set sensible defaults
			fmt.Printf("[WARN] Could not geolocate private IP %s via ip-api.com - setting as internal/private\n", log.ClientIP)
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

// checkAlienVaultOTX queries AlienVault OTX for IP reputation
// Free tier: Unlimited requests, no API key required
// AlienVault Open Threat Exchange is completely free and has no rate limits
func (es *EnrichmentService) checkAlienVaultOTX(ip string) (*ThreatIntelData, error) {
	// AlienVault OTX free API endpoint (no auth required)
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/IPv4/%s/general", ip)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	// AlienVault recommends User-Agent
	req.Header.Set("User-Agent", "WAF-SIEM-ThreatIntel/1.0")

	resp, err := es.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("alienvault otx request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("alienvault otx returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Log the complete raw JSON response for debugging
	fmt.Printf("[DEBUG] AlienVault OTX complete JSON response for IP %s:\n%s\n", ip, string(body))

	// Parse AlienVault OTX response
	var otxResp struct {
		Status          string `json:"status"`           // "success" or "fail"
		Message         string `json:"message"`          // Error message if fail
		Indicator       string `json:"indicator"`
		Type            string `json:"type"`
		ValidationCount int    `json:"validation_count"` // Number of validations (reputation)
		ThreatCount     int    `json:"threat_count"`     // Number of threats detected
		ExoneratedCount int    `json:"exonerated_count"`
		Pulses          []struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"pulses"` // Security threats/incidents
	}

	if err := json.Unmarshal(body, &otxResp); err != nil {
		return nil, fmt.Errorf("failed to parse alienvault otx response: %w", err)
	}

	// Check if the IP is in a reserved range (OTX returns "fail" status for these)
	if otxResp.Status == "fail" && otxResp.Message == "reserved range" {
		fmt.Printf("[INFO] IP %s is in a reserved range (carrier-grade NAT, special use, etc) - treating as safe\n", ip)
		// Return neutral data for reserved range IPs
		return &ThreatIntelData{
			IPReputation: 0,
			IsMalicious:  false,
			ThreatSource: "alienvault-otx",
			ThreatLevel:  "none",
		}, nil
	}

	fmt.Printf("[DEBUG] AlienVault OTX parsed for IP %s: validation_count=%d, threat_count=%d, pulses=%d\n",
		ip, otxResp.ValidationCount, otxResp.ThreatCount, len(otxResp.Pulses))

	// Calculate reputation based on threat count and pulses
	// threat_count and pulses indicate malicious activity
	reputation := 0
	isMalicious := false
	threatLevel := "none"

	if otxResp.ThreatCount > 0 || len(otxResp.Pulses) > 0 {
		isMalicious = true
		// Scale reputation based on threat/pulse count
		reputation = 20 + (otxResp.ThreatCount * 10) + (len(otxResp.Pulses) * 5)
		if reputation > 100 {
			reputation = 100
		}
		threatLevel = calculateThreatLevel(reputation)

		fmt.Printf("[INFO] AlienVault OTX detected threats for IP %s: reputation=%d, isMalicious=%v\n",
			ip, reputation, isMalicious)
	}

	data := &ThreatIntelData{
		IPReputation: reputation,
		IsMalicious:  isMalicious,
		AbuseReports: otxResp.ThreatCount + len(otxResp.Pulses),
		ThreatSource: "alienvault-otx",
		ThreatLevel:  threatLevel,
	}

	return data, nil
}

// checkGeoIP queries IP-API.com for geolocation and ASN info
// Free tier: 45 requests/minute, no API key required
// More reliable than ipapi.co with better rate limits
func (es *EnrichmentService) checkGeoIP(ip string) (*ThreatIntelData, error) {
	// IP-API.com endpoint - simple query endpoint for free tier
	url := fmt.Sprintf("http://ip-api.com/json/%s", ip)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Add User-Agent to comply with IP-API.com guidelines
	req.Header.Set("User-Agent", "WAF-SIEM-ThreatIntel/1.0")

	resp, err := es.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ip-api request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ip-api returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Log the complete raw JSON response for debugging
	fmt.Printf("[DEBUG] ip-api.com complete JSON response for IP %s:\n%s\n", ip, string(body))

	// IP-API.com response structure
	var apiResp struct {
		Status      string `json:"status"`       // "success" or "fail"
		Message     string `json:"message"`      // Error message if status is fail
		Country     string `json:"country"`      // Country name (e.g., "Switzerland")
		CountryCode string `json:"countryCode"` // ISO country code (e.g., "CH")
		Region      string `json:"region"`      // Region/State name
		RegionName  string `json:"regionName"`  // Region/State name
		City        string `json:"city"`        // City name
		ISP         string `json:"isp"`         // ISP name
		Org         string `json:"org"`         // Organization/Company
		AS          string `json:"as"`          // ASN in format "AS12345 Company"
		Timezone    string `json:"timezone"`    // Timezone
		Lat         float64 `json:"lat"`        // Latitude
		Lon         float64 `json:"lon"`        // Longitude
	}

	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse ip-api response: %w", err)
	}

	// Check if the query was successful
	if apiResp.Status != "success" {
		return nil, fmt.Errorf("ip-api query failed: %s", apiResp.Message)
	}

	// Log what we received for debugging
	fmt.Printf("[DEBUG] ip-api.com parsed response for IP %s: country=%s, countryCode=%s, isp=%s, org=%s, as=%s, city=%s\n",
		ip, apiResp.Country, apiResp.CountryCode, apiResp.ISP, apiResp.Org, apiResp.AS, apiResp.City)

	data := &ThreatIntelData{
		Country:      apiResp.CountryCode, // Use country code (CH, US, etc.)
		ISP:          apiResp.ISP,
		ASN:          parseASN(apiResp.AS), // IP-API returns AS field directly
		ThreatSource: "ip-api.com",
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
