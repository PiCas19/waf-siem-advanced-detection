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
	client    *http.Client
	cache     map[string]*CachedEnrichment
	cacheLock sync.RWMutex
	db        *gorm.DB
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
				reputationData, err := es.checkAlienVaultOTX(ipToGeolocate)
				if err == nil && reputationData != nil {
					data.IPReputation = reputationData.IPReputation
					data.IsMalicious = reputationData.IsMalicious
					data.ThreatLevel = reputationData.ThreatLevel
					data.AbuseReports = reputationData.AbuseReports
					data.ThreatSource = "alienvault-otx + ip-api.com"
				} else {
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

func (es *EnrichmentService) checkAlienVaultOTX(ip string) (*ThreatIntelData, error) {
	url := "https://otx.alienvault.com/api/v1/indicators/IPv4/" + ip + "/general"
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

	var otxResp struct {
		Status          string `json:"status"`
		Message         string `json:"message"`
		ValidationCount int    `json:"validation_count"`
		ThreatCount     int    `json:"threat_count"`
		Pulses          []struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"pulses"`
	}

	if err := json.Unmarshal(body, &otxResp); err != nil {
		return nil, err
	}

	if otxResp.Status == "fail" && otxResp.Message == "reserved range" {
		return &ThreatIntelData{
			IPReputation: 0,
			IsMalicious:  false,
			ThreatSource: "alienvault-otx",
			ThreatLevel:  "none",
		}, nil
	}

	reputation := 0
	isMalicious := false
	threatLevel := "none"

	if otxResp.ThreatCount > 0 || len(otxResp.Pulses) > 0 {
		isMalicious = true
		reputation = 20 + (otxResp.ThreatCount * 10) + (len(otxResp.Pulses) * 5)
		if reputation > 100 {
			reputation = 100
		}
		threatLevel = calculateThreatLevel(reputation)
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
