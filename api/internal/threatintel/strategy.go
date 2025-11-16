package threatintel

import (
	"fmt"
)

// ThreatIntelStrategy defines the interface for threat intelligence sources
type ThreatIntelStrategy interface {
	// Name returns the name of the strategy
	Name() string

	// IsAvailable checks if the strategy is configured and available
	IsAvailable() bool

	// Enrich performs threat intelligence enrichment for an IP
	Enrich(ip string) (*ThreatIntelData, error)

	// Priority returns the priority/weight for result combination (1-100)
	Priority() int
}

// StrategyResult wraps a strategy result with metadata
type StrategyResult struct {
	Strategy ThreatIntelStrategy
	Data     *ThreatIntelData
	Err      error
}

// Note: ThreatIntelData is defined in service.go to avoid conflicts
// This file extends and uses the ThreatIntelData type defined there

// Combine multiple strategy results using weighted averaging
func CombineResults(results []StrategyResult) *ThreatIntelData {
	if len(results) == 0 {
		return &ThreatIntelData{
			IPReputation:  0,
			IsMalicious:   false,
			ThreatLevel:   "none",
			ThreatSource:  "none",
		}
	}

	combined := &ThreatIntelData{
		IPReputation: 0,
		IsMalicious:  false,
		ThreatLevel:  "none",
		ThreatSource: "",
	}

	totalPriority := 0
	reputationSum := 0
	validReputations := 0
	sources := []string{}
	maxAbuseReports := 0

	for _, result := range results {
		if result.Err != nil || result.Data == nil {
			continue
		}

		data := result.Data
		priority := result.Strategy.Priority()
		totalPriority += priority

		// Combine IP reputation with weighted averaging
		if data.IPReputation > 0 {
			reputationSum += data.IPReputation * priority
			validReputations += priority
		}

		// Track if any strategy found malicious
		if data.IsMalicious {
			combined.IsMalicious = true
		}

		// Use first available country/ASN/ISP
		if combined.Country == "" && data.Country != "" {
			combined.Country = data.Country
		}
		if combined.ASN == "" && data.ASN != "" {
			combined.ASN = data.ASN
		}
		if combined.ISP == "" && data.ISP != "" {
			combined.ISP = data.ISP
		}

		// Accumulate abuse reports
		if data.AbuseReports > maxAbuseReports {
			maxAbuseReports = data.AbuseReports
		}

		// Track sources
		if data.ThreatSource != "" {
			sources = append(sources, data.ThreatSource)
		}

		// Update threat level if higher
		if GetThreatLevelScore(data.ThreatLevel) > GetThreatLevelScore(combined.ThreatLevel) {
			combined.ThreatLevel = data.ThreatLevel
		}
	}

	// Calculate weighted average reputation
	if validReputations > 0 {
		combined.IPReputation = reputationSum / validReputations
	}

	combined.AbuseReports = maxAbuseReports
	combined.ThreatSource = CombineSources(sources)

	return combined
}

// GetThreatLevelScore returns numeric score for threat level
func GetThreatLevelScore(level string) int {
	scores := map[string]int{
		"critical": 4,
		"high":     3,
		"medium":   2,
		"low":      1,
		"none":     0,
	}
	if score, ok := scores[level]; ok {
		return score
	}
	return 0
}

// CombineSources combines strategy sources into a single string
func CombineSources(sources []string) string {
	if len(sources) == 0 {
		return "none"
	}

	seen := make(map[string]bool)
	unique := []string{}
	for _, source := range sources {
		if !seen[source] && source != "" {
			seen[source] = true
			unique = append(unique, source)
		}
	}

	result := ""
	for i, source := range unique {
		if i > 0 {
			result += " + "
		}
		result += source
	}
	return result
}

// VirusTotalStrategy implements the ThreatIntelStrategy interface
type VirusTotalStrategy struct {
	enrichmentService *EnrichmentService
	apiKey            string
}

func NewVirusTotalStrategy(es *EnrichmentService, apiKey string) ThreatIntelStrategy {
	return &VirusTotalStrategy{
		enrichmentService: es,
		apiKey:            apiKey,
	}
}

func (v *VirusTotalStrategy) Name() string {
	return "VirusTotal"
}

func (v *VirusTotalStrategy) IsAvailable() bool {
	return v.apiKey != ""
}

func (v *VirusTotalStrategy) Priority() int {
	return 70 // 70% weight
}

func (v *VirusTotalStrategy) Enrich(ip string) (*ThreatIntelData, error) {
	return v.enrichmentService.checkVirusTotal(ip, v.apiKey)
}

// AbuseIPDBStrategy implements the ThreatIntelStrategy interface
type AbuseIPDBStrategy struct {
	enrichmentService *EnrichmentService
	apiKey            string
}

func NewAbuseIPDBStrategy(es *EnrichmentService, apiKey string) ThreatIntelStrategy {
	return &AbuseIPDBStrategy{
		enrichmentService: es,
		apiKey:            apiKey,
	}
}

func (a *AbuseIPDBStrategy) Name() string {
	return "AbuseIPDB"
}

func (a *AbuseIPDBStrategy) IsAvailable() bool {
	return a.apiKey != ""
}

func (a *AbuseIPDBStrategy) Priority() int {
	return 30 // 30% weight
}

func (a *AbuseIPDBStrategy) Enrich(ip string) (*ThreatIntelData, error) {
	return a.enrichmentService.checkAbuseIPDB(ip, a.apiKey)
}

// GeoIPStrategy implements the ThreatIntelStrategy interface
type GeoIPStrategy struct {
	enrichmentService *EnrichmentService
}

func NewGeoIPStrategy(es *EnrichmentService) ThreatIntelStrategy {
	return &GeoIPStrategy{
		enrichmentService: es,
	}
}

func (g *GeoIPStrategy) Name() string {
	return "GeoIP"
}

func (g *GeoIPStrategy) IsAvailable() bool {
	return true // Always available
}

func (g *GeoIPStrategy) Priority() int {
	return 10 // Low priority, just for geolocation
}

func (g *GeoIPStrategy) Enrich(ip string) (*ThreatIntelData, error) {
	return g.enrichmentService.checkGeoIP(ip)
}

// StrategyChain manages multiple strategies and combines results
type StrategyChain struct {
	strategies []ThreatIntelStrategy
}

func NewStrategyChain(strategies ...ThreatIntelStrategy) *StrategyChain {
	return &StrategyChain{
		strategies: strategies,
	}
}

// Execute runs all available strategies and combines results
func (sc *StrategyChain) Execute(ip string) (*ThreatIntelData, error) {
	if len(sc.strategies) == 0 {
		return nil, fmt.Errorf("no strategies configured")
	}

	results := make([]StrategyResult, 0)

	for _, strategy := range sc.strategies {
		if !strategy.IsAvailable() {
			continue
		}

		data, err := strategy.Enrich(ip)
		results = append(results, StrategyResult{
			Strategy: strategy,
			Data:     data,
			Err:      err,
		})
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no strategies returned valid data")
	}

	return CombineResults(results), nil
}

// Add adds a strategy to the chain
func (sc *StrategyChain) Add(strategy ThreatIntelStrategy) {
	sc.strategies = append(sc.strategies, strategy)
}
