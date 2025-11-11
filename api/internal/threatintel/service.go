package threatintel

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
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

// EnrichLog enriches a Log entry with threat intelligence data
func (es *EnrichmentService) EnrichLog(log *models.Log) error {
	// Skip private/local IPs
	if isPrivateIP(log.ClientIP) {
		return nil
	}

	// Check cache first
	if cached, exists := es.cache[log.ClientIP]; exists && time.Now().Before(cached.ExpiresAt) {
		applyThreatIntel(log, cached.Data)
		return nil
	}

	// Enrich from multiple sources
	data := &ThreatIntelData{}

	// 1. Try AbuseIPDB (primary source for IP reputation)
	abuseData, err := es.checkAbuseIPDB(log.ClientIP)
	if err == nil && abuseData != nil {
		data = abuseData
	} else {
		// 2. Fallback to ipapi.co for basic geolocation and ASN
		apiData, err := es.checkIPAPI(log.ClientIP)
		if err == nil && apiData != nil {
			data.ASN = apiData.ASN
			data.ISP = apiData.ISP
			data.Country = apiData.Country
			data.ThreatSource = "ipapi.co"
		}
	}

	// Cache the result (24 hour cache)
	es.cache[log.ClientIP] = &CachedEnrichment{
		Data:      data,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

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
