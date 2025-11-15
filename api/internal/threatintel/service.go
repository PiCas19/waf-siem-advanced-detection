package threatintel

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"gorm.io/gorm"
)

const httpTimeout = 5 * time.Second

type EnrichmentService struct {
	client         *http.Client
	cache          map[string]*CachedEnrichment
	cacheLock      sync.RWMutex
	db             *gorm.DB
	abuseIPDBKey   string
	virusTotalKey  string
}

type CachedEnrichment struct {
	Data      *ThreatIntelData
	ExpiresAt time.Time
}

type ThreatIntelData struct {
	IPReputation  int
	IsMalicious   bool
	ASN           string
	ISP           string
	Country       string
	ThreatLevel   string
	ThreatSource  string
	IsOnBlocklist bool
	BlocklistName string
	AbuseReports  int
}

func NewEnrichmentService() *EnrichmentService {
	return &EnrichmentService{
		client: &http.Client{
			Timeout: httpTimeout,
		},
		cache: make(map[string]*CachedEnrichment),
	}
}

func (es *EnrichmentService) SetDB(db *gorm.DB) {
	es.db = db
}

func (es *EnrichmentService) SetAbuseIPDBKey(apiKey string) {
	es.abuseIPDBKey = apiKey
}

func (es *EnrichmentService) SetVirusTotalKey(apiKey string) {
	es.virusTotalKey = apiKey
}

func (es *EnrichmentService) getFromCache(key string) (*CachedEnrichment, bool) {
	es.cacheLock.RLock()
	defer es.cacheLock.RUnlock()
	cached, exists := es.cache[key]
	return cached, exists
}

func (es *EnrichmentService) putInCache(key string, cached *CachedEnrichment) {
	es.cacheLock.Lock()
	defer es.cacheLock.Unlock()
	es.cache[key] = cached
}

func (es *EnrichmentService) EnrichLog(log *models.Log) error {
	isPrivate := isPrivateIP(log.ClientIP)
	isReserved := isReservedRange(log.ClientIP)
	isTailscaleVPN := log.ClientIPVPNReport

	if isReserved {
		if isTailscaleVPN {
			isPrivate = false
		} else {
			isPrivate = true
		}
	}

	cacheKey := log.ClientIP
	if isTailscaleVPN && log.ClientIPPublic != "" {
		cacheKey = log.ClientIPPublic
	}

	if cached, exists := es.getFromCache(cacheKey); exists && time.Now().Before(cached.ExpiresAt) {
		applyThreatIntel(log, cached.Data)
		return nil
	}

	data := &ThreatIntelData{}
	ipToGeolocate := log.ClientIP
	if isTailscaleVPN && log.ClientIPPublic != "" {
		ipToGeolocate = log.ClientIPPublic
		isPrivate = false
	}

	if !isPrivate {
		geoData, err := es.checkGeoIP(ipToGeolocate)
		if err == nil && geoData != nil {
			data = geoData
			if !isPrivate {
				// Try VirusTotal first (most comprehensive - 70+ vendors)
				vtData, vtErr := es.checkVirusTotal(ipToGeolocate, es.virusTotalKey)

				// Try AbuseIPDB as secondary source (abuse reports)
				abuseData, abuseErr := es.checkAbuseIPDB(ipToGeolocate, es.abuseIPDBKey)

				// Combine results using weighted scoring
				if vtErr == nil && vtData != nil && abuseErr == nil && abuseData != nil {
					// Both sources available - combine scores
					// VirusTotal gets 70% weight (more comprehensive detection)
					// AbuseIPDB gets 30% weight (community reports)
					data.IPReputation = combineReputationScores(vtData.IPReputation, abuseData.IPReputation, 70, 30)
					data.IsMalicious = vtData.IsMalicious || abuseData.IsMalicious
					data.AbuseReports = vtData.AbuseReports + abuseData.AbuseReports
					data.ThreatLevel = calculateThreatLevel(data.IPReputation)
					data.ThreatSource = "virustotal + abuseipdb + ip-api.com"
				} else if vtErr == nil && vtData != nil {
					// Only VirusTotal available
					data.IPReputation = vtData.IPReputation
					data.IsMalicious = vtData.IsMalicious
					data.AbuseReports = vtData.AbuseReports
					data.ThreatLevel = vtData.ThreatLevel
					data.ThreatSource = "virustotal + ip-api.com"
				} else if abuseErr == nil && abuseData != nil {
					// Only AbuseIPDB available
					data.IPReputation = abuseData.IPReputation
					data.IsMalicious = abuseData.IsMalicious
					data.AbuseReports = abuseData.AbuseReports
					data.ThreatLevel = abuseData.ThreatLevel
					data.ThreatSource = "abuseipdb + ip-api.com"
				} else {
					// No reputation data available
					data.ThreatSource = "ip-api.com"
				}
			}
		} else {
			if isTailscaleVPN && log.ClientIPPublic != "" {
				data.Country = "VPN/TAILSCALE"
				data.ISP = "Tailscale VPN Network"
				data.ThreatSource = "tailscale-vpn"
				data.ThreatLevel = "low"
			} else if isTailscaleVPN {
				data.Country = "VPN/TAILSCALE"
				data.ISP = "Tailscale VPN Network"
				data.ThreatSource = "tailscale-vpn"
				data.ThreatLevel = "low"
			} else {
				data.Country = "PRIVATE"
				data.ISP = "Internal/Private Network"
				data.ThreatSource = "internal"
				data.ThreatLevel = "low"
			}
		}
	}

	if es.db != nil {
		var blockedIP models.BlockedIP
		now := time.Now()
		err := es.db.Where("ip_address = ? AND (description = ? OR description = ?) AND (permanent = ? OR expires_at > ?)",
			log.ClientIP, log.ThreatType, "GLOBAL", true, now).First(&blockedIP).Error
		if err == nil {
			data.IsOnBlocklist = true
			data.BlocklistName = blockedIP.Description
		}
	}

	es.putInCache(cacheKey, &CachedEnrichment{
		Data:      data,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})

	applyThreatIntel(log, data)
	return nil
}

func (es *EnrichmentService) checkVirusTotal(ip string, apiKey string) (*ThreatIntelData, error) {
	if apiKey == "" {
		return nil, nil // Skip if API key not configured
	}

	url := "https://www.virustotal.com/api/v3/ip_addresses/" + ip
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "WAF-SIEM-ThreatIntel/1.0")
	req.Header.Set("x-apikey", apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := es.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var vtResp struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious   int `json:"malicious"`
					Suspicious  int `json:"suspicious"`
					Undetected  int `json:"undetected"`
					Harmless    int `json:"harmless"`
					Timeout     int `json:"timeout"`
				} `json:"last_analysis_stats"`
				AsnOrganization string `json:"asn_organization"`
				Country         string `json:"country"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &vtResp); err != nil {
		return nil, err
	}

	// Calculate reputation score based on detection ratio
	stats := vtResp.Data.Attributes.LastAnalysisStats
	totalEngines := stats.Malicious + stats.Suspicious + stats.Undetected + stats.Harmless

	reputation := 0
	isMalicious := false

	if totalEngines > 0 {
		// Score based on percentage of detections
		detectionRatio := (stats.Malicious * 100) / totalEngines

		// Malicious gets full weight, Suspicious gets half weight
		suspiciousRatio := (stats.Suspicious * 50) / totalEngines
		reputation = detectionRatio + suspiciousRatio

		if reputation > 100 {
			reputation = 100
		}

		isMalicious = stats.Malicious > 0 || stats.Suspicious > 2
	}

	threatLevel := calculateThreatLevel(reputation)

	data := &ThreatIntelData{
		IPReputation: reputation,
		IsMalicious:  isMalicious,
		AbuseReports: stats.Malicious + stats.Suspicious,
		ThreatSource: "virustotal",
		ThreatLevel:  threatLevel,
	}
	return data, nil
}

func (es *EnrichmentService) checkAbuseIPDB(ip string, apiKey string) (*ThreatIntelData, error) {
	if apiKey == "" {
		return nil, nil // Skip if API key not configured
	}

	url := "https://api.abuseipdb.com/api/v2/check"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	q := req.URL.Query()
	q.Add("ipAddress", ip)
	q.Add("maxAgeInDays", "90")
	q.Add("verbose", "")
	req.URL.RawQuery = q.Encode()

	req.Header.Set("User-Agent", "WAF-SIEM-ThreatIntel/1.0")
	req.Header.Set("Key", apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := es.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var abuseResp struct {
		Data struct {
			AbuseConfidenceScore int `json:"abuseConfidenceScore"`
			Reports              int `json:"totalReports"`
			Hostnames            []struct {
				Name string `json:"hostname"`
			} `json:"hostnames"`
			ReportedCategories []int `json:"reportedCategories"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &abuseResp); err != nil {
		return nil, err
	}

	reputation := abuseResp.Data.AbuseConfidenceScore
	isMalicious := reputation > 25 // Consider suspicious if score > 25
	threatLevel := calculateThreatLevel(reputation)

	data := &ThreatIntelData{
		IPReputation: reputation,
		IsMalicious:  isMalicious,
		AbuseReports: abuseResp.Data.Reports,
		ThreatSource: "abuseipdb",
		ThreatLevel:  threatLevel,
	}
	return data, nil
}

func (es *EnrichmentService) checkGeoIP(ip string) (*ThreatIntelData, error) {
	url := "http://ip-api.com/json/" + ip
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "WAF-SIEM-ThreatIntel/1.0")
	resp, err := es.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var apiResp struct {
		Status      string `json:"status"`
		Message     string `json:"message"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		ISP         string `json:"isp"`
		AS          string `json:"as"`
	}

	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, err
	}

	if apiResp.Status != "success" {
		return nil, err
	}

	data := &ThreatIntelData{
		Country:      apiResp.CountryCode,
		ISP:          apiResp.ISP,
		ASN:          parseASN(apiResp.AS),
		ThreatSource: "ip-api.com",
	}
	return data, nil
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true
	}
	return ip.IsPrivate() || ip.IsLoopback()
}

func isReservedRange(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	cgn := net.IPNet{IP: net.ParseIP("100.64.0.0"), Mask: net.CIDRMask(10, 32)}
	if cgn.Contains(ip) {
		return true
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsMulticast() {
		return true
	}
	return false
}

func parseASN(org string) string {
	if len(org) < 2 {
		return ""
	}
	if org[0:2] == "AS" {
		for i, ch := range org {
			if ch < '0' || ch > '9' {
				if i > 2 {
					return org[0:i]
				}
				break
			}
		}
	}
	return org
}

// combineReputationScores combines two reputation scores using weighted average
// score1Weight is the weight for the first score (VirusTotal in our case)
// score2Weight is the weight for the second score (AbuseIPDB in our case)
func combineReputationScores(score1, score2 int, weight1, weight2 int) int {
	// If one source is 0 and the other is valid, use the valid one
	if score1 == 0 && score2 > 0 {
		return score2
	}
	if score2 == 0 && score1 > 0 {
		return score1
	}
	if score1 == 0 && score2 == 0 {
		return 0
	}

	// Weighted average based on provided weights
	totalWeight := weight1 + weight2
	combined := (score1 * weight1 / totalWeight) + (score2 * weight2 / totalWeight)
	if combined > 100 {
		combined = 100
	}
	return combined
}

func calculateThreatLevel(score int) string {
	// Improved threat level calculation with better granularity
	// Based on industry-standard reputation scoring practices
	switch {
	case score >= 90:
		return "critical" // Almost certainly malicious
	case score >= 75:
		return "critical" // Highly suspicious, strong indicators
	case score >= 60:
		return "high" // Strong indicators of malicious activity
	case score >= 40:
		return "high" // Moderate-to-strong indicators
	case score >= 25:
		return "medium" // Some indicators of suspicious activity
	case score >= 10:
		return "low" // Minor indicators, needs monitoring
	case score > 0:
		return "low" // Minimal indicators
	default:
		return "none" // Clean or no data
	}
}

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
