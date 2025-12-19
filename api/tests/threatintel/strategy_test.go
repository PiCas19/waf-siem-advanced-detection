package threatintel

import (
	"testing"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/threatintel"
	"github.com/stretchr/testify/assert"
)

// TestGetThreatLevelScore tests threat level to score conversion
func TestGetThreatLevelScore(t *testing.T) {
	tests := []struct {
		name     string
		level    string
		expected int
	}{
		{"Critical", "critical", 4},
		{"High", "high", 3},
		{"Medium", "medium", 2},
		{"Low", "low", 1},
		{"None", "none", 0},
		{"Unknown", "unknown", 0},
		{"Empty", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := threatintel.GetThreatLevelScore(tt.level)
			assert.Equal(t, tt.expected, score)
		})
	}
}

// TestCombineSources tests source combining
func TestCombineSources(t *testing.T) {
	tests := []struct {
		name     string
		sources  []string
		expected string
	}{
		{
			"Single source",
			[]string{"virustotal"},
			"virustotal",
		},
		{
			"Multiple sources",
			[]string{"virustotal", "abuseipdb"},
			"virustotal + abuseipdb",
		},
		{
			"Duplicate sources",
			[]string{"virustotal", "virustotal", "abuseipdb"},
			"virustotal + abuseipdb",
		},
		{
			"Empty list",
			[]string{},
			"none",
		},
		{
			"With empty strings",
			[]string{"virustotal", "", "abuseipdb", ""},
			"virustotal + abuseipdb",
		},
		{
			"Three sources",
			[]string{"virustotal", "abuseipdb", "ip-api.com"},
			"virustotal + abuseipdb + ip-api.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := threatintel.CombineSources(tt.sources)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestCombineResults_EmptyResults tests combining with no results
func TestCombineResults_EmptyResults(t *testing.T) {
	results := []threatintel.StrategyResult{}

	combined := threatintel.CombineResults(results)

	assert.NotNil(t, combined)
	assert.Equal(t, 0, combined.IPReputation)
	assert.False(t, combined.IsMalicious)
	assert.Equal(t, "none", combined.ThreatLevel)
	assert.Equal(t, "none", combined.ThreatSource)
}

// TestCombineResults_SingleResult tests combining with one result
func TestCombineResults_SingleResult(t *testing.T) {
	data := &threatintel.ThreatIntelData{
		IPReputation: 80,
		IsMalicious:  true,
		ASN:          "AS15169",
		ISP:          "Google LLC",
		Country:      "US",
		ThreatLevel:  "high",
		ThreatSource: "virustotal",
		AbuseReports: 5,
	}

	strategy := &mockStrategy{
		name:      "VirusTotal",
		priority:  70,
		available: true,
	}

	results := []threatintel.StrategyResult{
		{
			Strategy: strategy,
			Data:     data,
			Err:      nil,
		},
	}

	combined := threatintel.CombineResults(results)

	assert.Equal(t, 80, combined.IPReputation)
	assert.True(t, combined.IsMalicious)
	assert.Equal(t, "US", combined.Country)
	assert.Equal(t, "AS15169", combined.ASN)
	assert.Equal(t, "Google LLC", combined.ISP)
	assert.Equal(t, "high", combined.ThreatLevel)
	assert.Equal(t, "virustotal", combined.ThreatSource)
	assert.Equal(t, 5, combined.AbuseReports)
}

// TestCombineResults_MultipleResults tests weighted combining
func TestCombineResults_MultipleResults(t *testing.T) {
	vtData := &threatintel.ThreatIntelData{
		IPReputation: 100,
		IsMalicious:  true,
		ThreatLevel:  "critical",
		ThreatSource: "virustotal",
		AbuseReports: 10,
	}

	abuseData := &threatintel.ThreatIntelData{
		IPReputation: 50,
		IsMalicious:  false,
		ThreatLevel:  "medium",
		ThreatSource: "abuseipdb",
		AbuseReports: 3,
	}

	geoData := &threatintel.ThreatIntelData{
		IPReputation: 0,
		Country:      "US",
		ASN:          "AS15169",
		ISP:          "Google LLC",
		ThreatSource: "ip-api.com",
	}

	vtStrategy := &mockStrategy{name: "VirusTotal", priority: 70, available: true}
	abuseStrategy := &mockStrategy{name: "AbuseIPDB", priority: 30, available: true}
	geoStrategy := &mockStrategy{name: "GeoIP", priority: 10, available: true}

	results := []threatintel.StrategyResult{
		{Strategy: vtStrategy, Data: vtData, Err: nil},
		{Strategy: abuseStrategy, Data: abuseData, Err: nil},
		{Strategy: geoStrategy, Data: geoData, Err: nil},
	}

	combined := threatintel.CombineResults(results)

	// Reputation should be weighted average: (100*70 + 50*30) / (70+30) = 85
	assert.Equal(t, 85, combined.IPReputation)

	// IsMalicious should be true if any source says true
	assert.True(t, combined.IsMalicious)

	// Threat level should be highest
	assert.Equal(t, "critical", combined.ThreatLevel)

	// Should have geo data
	assert.Equal(t, "US", combined.Country)
	assert.Equal(t, "AS15169", combined.ASN)

	// Abuse reports should be max
	assert.Equal(t, 10, combined.AbuseReports)

	// Sources should be combined
	assert.Contains(t, combined.ThreatSource, "virustotal")
	assert.Contains(t, combined.ThreatSource, "abuseipdb")
}

// TestCombineResults_WithErrors tests combining with some failed results
func TestCombineResults_WithErrors(t *testing.T) {
	goodData := &threatintel.ThreatIntelData{
		IPReputation: 60,
		IsMalicious:  true,
		ThreatLevel:  "medium",
		ThreatSource: "virustotal",
	}

	goodStrategy := &mockStrategy{name: "VirusTotal", priority: 70, available: true}
	badStrategy := &mockStrategy{name: "AbuseIPDB", priority: 30, available: true}

	results := []threatintel.StrategyResult{
		{Strategy: goodStrategy, Data: goodData, Err: nil},
		{Strategy: badStrategy, Data: nil, Err: assert.AnError},
	}

	combined := threatintel.CombineResults(results)

	// Should use only the good result
	assert.Equal(t, 60, combined.IPReputation)
	assert.True(t, combined.IsMalicious)
	assert.Equal(t, "medium", combined.ThreatLevel)
}

// TestCombineResults_AllErrors tests combining when all results are errors
func TestCombineResults_AllErrors(t *testing.T) {
	s1 := &mockStrategy{name: "VT", priority: 70, available: true}
	s2 := &mockStrategy{name: "Abuse", priority: 30, available: true}

	results := []threatintel.StrategyResult{
		{Strategy: s1, Data: nil, Err: assert.AnError},
		{Strategy: s2, Data: nil, Err: assert.AnError},
	}

	combined := threatintel.CombineResults(results)

	// Should return safe defaults
	assert.Equal(t, 0, combined.IPReputation)
	assert.False(t, combined.IsMalicious)
	assert.Equal(t, "none", combined.ThreatLevel)
}

// TestCombineResults_DifferentThreatLevels tests threat level priority
func TestCombineResults_DifferentThreatLevels(t *testing.T) {
	tests := []struct {
		name      string
		levels    []string
		expected  string
	}{
		{
			"Critical wins",
			[]string{"low", "medium", "critical"},
			"critical",
		},
		{
			"High wins over medium",
			[]string{"low", "medium", "high"},
			"high",
		},
		{
			"Medium wins over low",
			[]string{"low", "medium", "low"},
			"medium",
		},
		{
			"All same",
			[]string{"medium", "medium", "medium"},
			"medium",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := []threatintel.StrategyResult{}

			for i, level := range tt.levels {
				data := &threatintel.ThreatIntelData{
					ThreatLevel:  level,
					ThreatSource: "test",
				}
				strategy := &mockStrategy{
					name:      "test",
					priority:  10,
					available: true,
				}
				results = append(results, threatintel.StrategyResult{
					Strategy: strategy,
					Data:     data,
					Err:      nil,
				})
				_ = i
			}

			combined := threatintel.CombineResults(results)
			assert.Equal(t, tt.expected, combined.ThreatLevel)
		})
	}
}

// TestVirusTotalStrategy tests VirusTotal strategy
func TestVirusTotalStrategy(t *testing.T) {
	service := threatintel.NewEnrichmentService()
	apiKey := "test-vt-key"

	strategy := threatintel.NewVirusTotalStrategy(service, apiKey)

	assert.Equal(t, "VirusTotal", strategy.Name())
	assert.True(t, strategy.IsAvailable())
	assert.Equal(t, 70, strategy.Priority())
}

// TestVirusTotalStrategy_NoKey tests VirusTotal without API key
func TestVirusTotalStrategy_NoKey(t *testing.T) {
	service := threatintel.NewEnrichmentService()

	strategy := threatintel.NewVirusTotalStrategy(service, "")

	assert.Equal(t, "VirusTotal", strategy.Name())
	assert.False(t, strategy.IsAvailable())
	assert.Equal(t, 70, strategy.Priority())
}

// TestAbuseIPDBStrategy tests AbuseIPDB strategy
func TestAbuseIPDBStrategy(t *testing.T) {
	service := threatintel.NewEnrichmentService()
	apiKey := "test-abuse-key"

	strategy := threatintel.NewAbuseIPDBStrategy(service, apiKey)

	assert.Equal(t, "AbuseIPDB", strategy.Name())
	assert.True(t, strategy.IsAvailable())
	assert.Equal(t, 30, strategy.Priority())
}

// TestAbuseIPDBStrategy_NoKey tests AbuseIPDB without API key
func TestAbuseIPDBStrategy_NoKey(t *testing.T) {
	service := threatintel.NewEnrichmentService()

	strategy := threatintel.NewAbuseIPDBStrategy(service, "")

	assert.Equal(t, "AbuseIPDB", strategy.Name())
	assert.False(t, strategy.IsAvailable())
	assert.Equal(t, 30, strategy.Priority())
}

// TestGeoIPStrategy tests GeoIP strategy
func TestGeoIPStrategy(t *testing.T) {
	service := threatintel.NewEnrichmentService()

	strategy := threatintel.NewGeoIPStrategy(service)

	assert.Equal(t, "GeoIP", strategy.Name())
	assert.True(t, strategy.IsAvailable()) // Always available
	assert.Equal(t, 10, strategy.Priority())
}

// TestStrategyChain_Empty tests empty strategy chain
func TestStrategyChain_Empty(t *testing.T) {
	chain := threatintel.NewStrategyChain()

	_, err := chain.Execute("8.8.8.8")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no strategies")
}

// TestStrategyChain_SingleStrategy tests chain with one strategy
func TestStrategyChain_SingleStrategy(t *testing.T) {
	service := threatintel.NewEnrichmentService()
	strategy := threatintel.NewGeoIPStrategy(service)

	chain := threatintel.NewStrategyChain(strategy)

	result, err := chain.Execute("8.8.8.8")

	// May fail due to network, but should not panic
	_ = result
	_ = err
}

// TestStrategyChain_MultipleStrategies tests chain with multiple strategies
func TestStrategyChain_MultipleStrategies(t *testing.T) {
	service := threatintel.NewEnrichmentService()

	vtStrategy := threatintel.NewVirusTotalStrategy(service, "") // No key
	abuseStrategy := threatintel.NewAbuseIPDBStrategy(service, "") // No key
	geoStrategy := threatintel.NewGeoIPStrategy(service)

	chain := threatintel.NewStrategyChain(vtStrategy, abuseStrategy, geoStrategy)

	result, err := chain.Execute("8.8.8.8")

	// GeoIP should work, others will skip due to no API keys
	_ = result
	_ = err
}

// TestStrategyChain_Add tests adding strategies
func TestStrategyChain_Add(t *testing.T) {
	service := threatintel.NewEnrichmentService()

	chain := threatintel.NewStrategyChain()

	strategy1 := threatintel.NewGeoIPStrategy(service)
	chain.Add(strategy1)

	strategy2 := threatintel.NewVirusTotalStrategy(service, "test-key")
	chain.Add(strategy2)

	// Chain should now have 2 strategies
	result, err := chain.Execute("1.1.1.1")
	_ = result
	_ = err
}

// TestStrategyChain_OnlyUnavailable tests chain with only unavailable strategies
func TestStrategyChain_OnlyUnavailable(t *testing.T) {
	service := threatintel.NewEnrichmentService()

	// Both strategies unavailable (no API keys)
	vtStrategy := threatintel.NewVirusTotalStrategy(service, "")
	abuseStrategy := threatintel.NewAbuseIPDBStrategy(service, "")

	chain := threatintel.NewStrategyChain(vtStrategy, abuseStrategy)

	_, err := chain.Execute("8.8.8.8")

	// Should error as no strategies returned data
	assert.Error(t, err)
}

// TestCombineResults_MaxAbuseReports tests that max abuse reports is used
func TestCombineResults_MaxAbuseReports(t *testing.T) {
	data1 := &threatintel.ThreatIntelData{
		AbuseReports: 5,
		ThreatSource: "source1",
	}

	data2 := &threatintel.ThreatIntelData{
		AbuseReports: 15,
		ThreatSource: "source2",
	}

	data3 := &threatintel.ThreatIntelData{
		AbuseReports: 10,
		ThreatSource: "source3",
	}

	s1 := &mockStrategy{name: "s1", priority: 30, available: true}
	s2 := &mockStrategy{name: "s2", priority: 40, available: true}
	s3 := &mockStrategy{name: "s3", priority: 30, available: true}

	results := []threatintel.StrategyResult{
		{Strategy: s1, Data: data1, Err: nil},
		{Strategy: s2, Data: data2, Err: nil},
		{Strategy: s3, Data: data3, Err: nil},
	}

	combined := threatintel.CombineResults(results)

	// Should use maximum abuse reports
	assert.Equal(t, 15, combined.AbuseReports)
}

// TestCombineResults_FirstNonEmptyGeoData tests that first available geo data is used
func TestCombineResults_FirstNonEmptyGeoData(t *testing.T) {
	data1 := &threatintel.ThreatIntelData{
		Country:      "",
		ASN:          "",
		ISP:          "",
		ThreatSource: "source1",
	}

	data2 := &threatintel.ThreatIntelData{
		Country:      "US",
		ASN:          "AS15169",
		ISP:          "Google LLC",
		ThreatSource: "source2",
	}

	data3 := &threatintel.ThreatIntelData{
		Country:      "DE",
		ASN:          "AS3320",
		ISP:          "Deutsche Telekom",
		ThreatSource: "source3",
	}

	s1 := &mockStrategy{name: "s1", priority: 30, available: true}
	s2 := &mockStrategy{name: "s2", priority: 40, available: true}
	s3 := &mockStrategy{name: "s3", priority: 30, available: true}

	results := []threatintel.StrategyResult{
		{Strategy: s1, Data: data1, Err: nil},
		{Strategy: s2, Data: data2, Err: nil},
		{Strategy: s3, Data: data3, Err: nil},
	}

	combined := threatintel.CombineResults(results)

	// Should use first non-empty values (data2)
	assert.Equal(t, "US", combined.Country)
	assert.Equal(t, "AS15169", combined.ASN)
	assert.Equal(t, "Google LLC", combined.ISP)
}

// TestCombineResults_ZeroReputations tests combining with zero reputations
func TestCombineResults_ZeroReputations(t *testing.T) {
	data1 := &threatintel.ThreatIntelData{
		IPReputation: 0,
		ThreatSource: "source1",
	}

	data2 := &threatintel.ThreatIntelData{
		IPReputation: 0,
		ThreatSource: "source2",
	}

	s1 := &mockStrategy{name: "s1", priority: 50, available: true}
	s2 := &mockStrategy{name: "s2", priority: 50, available: true}

	results := []threatintel.StrategyResult{
		{Strategy: s1, Data: data1, Err: nil},
		{Strategy: s2, Data: data2, Err: nil},
	}

	combined := threatintel.CombineResults(results)

	assert.Equal(t, 0, combined.IPReputation)
}

// Mock strategy for testing
type mockStrategy struct {
	name      string
	priority  int
	available bool
	data      *threatintel.ThreatIntelData
	err       error
}

func (m *mockStrategy) Name() string {
	return m.name
}

func (m *mockStrategy) IsAvailable() bool {
	return m.available
}

func (m *mockStrategy) Priority() int {
	return m.priority
}

func (m *mockStrategy) Enrich(ip string) (*threatintel.ThreatIntelData, error) {
	return m.data, m.err
}

// TestStrategyInterface tests that all strategies implement the interface
func TestStrategyInterface(t *testing.T) {
	service := threatintel.NewEnrichmentService()

	strategies := []threatintel.ThreatIntelStrategy{
		threatintel.NewVirusTotalStrategy(service, "key"),
		threatintel.NewAbuseIPDBStrategy(service, "key"),
		threatintel.NewGeoIPStrategy(service),
	}

	for _, strategy := range strategies {
		assert.NotEmpty(t, strategy.Name())
		assert.GreaterOrEqual(t, strategy.Priority(), 0)
		// IsAvailable varies by strategy
		// Enrich requires network call, not testing here
	}
}

// TestCombineResults_MixedMalicious tests malicious flag combining
func TestCombineResults_MixedMalicious(t *testing.T) {
	tests := []struct {
		name        string
		malicious   []bool
		expectMal   bool
	}{
		{"All malicious", []bool{true, true, true}, true},
		{"None malicious", []bool{false, false, false}, false},
		{"One malicious", []bool{false, true, false}, true},
		{"Two malicious", []bool{true, true, false}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := []threatintel.StrategyResult{}

			for i, mal := range tt.malicious {
				data := &threatintel.ThreatIntelData{
					IsMalicious:  mal,
					ThreatSource: "test",
				}
				strategy := &mockStrategy{
					name:      "test",
					priority:  10,
					available: true,
				}
				results = append(results, threatintel.StrategyResult{
					Strategy: strategy,
					Data:     data,
					Err:      nil,
				})
				_ = i
			}

			combined := threatintel.CombineResults(results)
			assert.Equal(t, tt.expectMal, combined.IsMalicious)
		})
	}
}

// TestNewStrategyChain_Variadic tests variadic constructor
func TestNewStrategyChain_Variadic(t *testing.T) {
	service := threatintel.NewEnrichmentService()

	s1 := threatintel.NewGeoIPStrategy(service)
	s2 := threatintel.NewVirusTotalStrategy(service, "key")
	s3 := threatintel.NewAbuseIPDBStrategy(service, "key")

	// Test with different numbers of strategies
	chain0 := threatintel.NewStrategyChain()
	assert.NotNil(t, chain0)

	chain1 := threatintel.NewStrategyChain(s1)
	assert.NotNil(t, chain1)

	chain2 := threatintel.NewStrategyChain(s1, s2)
	assert.NotNil(t, chain2)

	chain3 := threatintel.NewStrategyChain(s1, s2, s3)
	assert.NotNil(t, chain3)
}

// TestCombineResults_WeightedAverageCalculation tests reputation calculation
func TestCombineResults_WeightedAverageCalculation(t *testing.T) {
	tests := []struct {
		name       string
		reputations []int
		priorities  []int
		expected    int
	}{
		{
			"Equal weights",
			[]int{50, 50},
			[]int{50, 50},
			50,
		},
		{
			"70-30 split",
			[]int{100, 0},
			[]int{70, 30},
			100, // Zero reputation is ignored, so only 100 is used
		},
		{
			"Different values",
			[]int{80, 40},
			[]int{60, 40},
			64, // (80*60 + 40*40) / 100 = 64
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := []threatintel.StrategyResult{}

			for i := range tt.reputations {
				data := &threatintel.ThreatIntelData{
					IPReputation: tt.reputations[i],
					ThreatSource: "test",
				}
				strategy := &mockStrategy{
					name:      "test",
					priority:  tt.priorities[i],
					available: true,
				}
				results = append(results, threatintel.StrategyResult{
					Strategy: strategy,
					Data:     data,
					Err:      nil,
				})
			}

			combined := threatintel.CombineResults(results)
			assert.Equal(t, tt.expected, combined.IPReputation)
		})
	}
}
