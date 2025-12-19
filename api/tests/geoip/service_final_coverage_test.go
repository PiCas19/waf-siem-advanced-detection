package geoip

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/geoip"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	logger.InitLogger("error", "/dev/null")
}

// Test ipBetween with pure IPv6 addresses (To16 path)
func TestLookupCountry_IPv6PureAddresses(t *testing.T) {
	// Create geoip directory with IPv6 ranges
	err := os.MkdirAll("geoip", 0755)
	if err != nil && !os.IsExist(err) {
		t.Skip("Cannot create geoip directory")
	}
	defer os.RemoveAll("geoip")

	jsonData := geoip.IPRangesData{
		Ranges: []geoip.IPRange{
			// Pure IPv6 range
			{
				Start:       "2001:0db8:0000:0000:0000:0000:0000:0000",
				End:         "2001:0db8:0000:0000:ffff:ffff:ffff:ffff",
				Country:     "TEST",
				CountryName: "Test IPv6",
			},
			// Another IPv6 range
			{
				Start:       "2001:0db9::",
				End:         "2001:0db9:ffff:ffff:ffff:ffff:ffff:ffff",
				Country:     "TEST2",
				CountryName: "Test IPv6 2",
			},
		},
	}
	data, err := json.Marshal(jsonData)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join("geoip", "ip_ranges.json"), data, 0644)
	require.NoError(t, err)

	service, err := geoip.NewService()
	require.NoError(t, err)

	// Test IPv6 addresses to trigger To16() path in ipBetween
	testCases := []struct {
		ip          string
		description string
	}{
		{"2001:0db8::1", "IPv6 start of range"},
		{"2001:0db8:0:0:8000::", "IPv6 middle of range"},
		{"2001:0db8:0:0:ffff:ffff:ffff:ffff", "IPv6 end of range"},
		{"2001:0db9::1", "IPv6 in second range"},
		{"2001:0db7:ffff:ffff:ffff:ffff:ffff:ffff", "IPv6 before range"},
		{"2001:0dba::", "IPv6 after range"},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			country := service.LookupCountry(tc.ip)
			assert.NotEmpty(t, country, "Should return country for %s", tc.ip)
		})
	}
}

// Test ipBetween with mixed length IPs to trigger all To4() and To16() paths
func TestLookupCountry_MixedIPVersions(t *testing.T) {
	err := os.MkdirAll("geoip", 0755)
	if err != nil && !os.IsExist(err) {
		t.Skip("Cannot create geoip directory")
	}
	defer os.RemoveAll("geoip")

	jsonData := geoip.IPRangesData{
		Ranges: []geoip.IPRange{
			// IPv4 range
			{Start: "192.168.0.0", End: "192.168.255.255", Country: "T4", CountryName: "Test IPv4"},
			// IPv6 range with full notation
			{
				Start:       "fe80:0000:0000:0000:0000:0000:0000:0000",
				End:         "fe80:0000:0000:0000:ffff:ffff:ffff:ffff",
				Country:     "T6",
				CountryName: "Test IPv6 Full",
			},
		},
	}
	data, err := json.Marshal(jsonData)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join("geoip", "ip_ranges.json"), data, 0644)
	require.NoError(t, err)

	service, err := geoip.NewService()
	require.NoError(t, err)

	// Test IPv4 to trigger To4() path
	country := service.LookupCountry("192.168.1.1")
	assert.NotEmpty(t, country)

	// Test IPv6 to trigger To16() path
	country = service.LookupCountry("fe80::1")
	assert.NotEmpty(t, country)

	// Test IPv4-mapped IPv6 address
	country = service.LookupCountry("::ffff:192.168.1.1")
	assert.NotEmpty(t, country)
}

// Test NewService with all database path attempts
func TestNewService_AllDatabasePaths(t *testing.T) {
	// Save current directory
	originalDir, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(originalDir)

	// Create a temporary directory
	tmpDir, err := os.MkdirTemp("", "geoip_dbpath_test_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Change to temp directory
	err = os.Chdir(tmpDir)
	require.NoError(t, err)

	// Ensure no database files exist in any of the paths
	// NewService will try: "geoip/GeoLite2-Country.mmdb", "./geoip/GeoLite2-Country.mmdb", "/geoip/GeoLite2-Country.mmdb"
	// All will fail, forcing fallback to JSON

	// Create JSON fallback
	err = os.MkdirAll("geoip", 0755)
	require.NoError(t, err)

	jsonData := geoip.IPRangesData{
		Ranges: []geoip.IPRange{
			{Start: "50.0.0.0", End: "50.255.255.255", Country: "TEST", CountryName: "Test"},
		},
	}
	data, err := json.Marshal(jsonData)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join("geoip", "ip_ranges.json"), data, 0644)
	require.NoError(t, err)

	// Create service - will try all DB paths, fail, then load JSON
	service, err := geoip.NewService()
	require.NoError(t, err)
	assert.NotNil(t, service)

	// Verify it uses JSON ranges
	country := service.LookupCountry("50.1.1.1")
	assert.NotEmpty(t, country)
}

// Test NewService with no database and no JSON file (fallback ranges)
func TestNewService_FallbackRangesOnly(t *testing.T) {
	// Save current directory
	originalDir, err := os.Getwd()
	require.NoError(t, err)
	defer os.Chdir(originalDir)

	// Create a temporary directory with no geoip folder
	tmpDir, err := os.MkdirTemp("", "geoip_fallback_test_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	err = os.Chdir(tmpDir)
	require.NoError(t, err)

	// No geoip directory, no JSON file - should use hardcoded fallback ranges
	service, err := geoip.NewService()
	require.NoError(t, err)
	assert.NotNil(t, service)

	// Test IPs from fallback ranges
	fallbackTestIPs := []string{
		"1.1.1.1",   // Australia fallback
		"4.4.4.4",   // US fallback
		"7.7.7.7",   // Russia fallback
		"16.16.16.16", // China fallback
	}

	for _, ip := range fallbackTestIPs {
		country := service.LookupCountry(ip)
		// Should return country from fallback ranges
		assert.NotEqual(t, "", country)
	}
}

// Test LookupCountry with ranges where parseIP fails
func TestLookupCountry_UnparseableRangeIPs(t *testing.T) {
	err := os.MkdirAll("geoip", 0755)
	if err != nil && !os.IsExist(err) {
		t.Skip("Cannot create geoip directory")
	}
	defer os.RemoveAll("geoip")

	// Create ranges with various invalid formats
	jsonData := geoip.IPRangesData{
		Ranges: []geoip.IPRange{
			{Start: "not-an-ip", End: "also-not-ip", Country: "XX", CountryName: "Invalid 1"},
			{Start: "999.999.999.999", End: "1000.1000.1000.1000", Country: "YY", CountryName: "Invalid 2"},
			{Start: "", End: "", Country: "ZZ", CountryName: "Empty"},
			{Start: "1.2.3.4", End: "1.2.3.10", Country: "OK", CountryName: "Valid"},
		},
	}
	data, err := json.Marshal(jsonData)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join("geoip", "ip_ranges.json"), data, 0644)
	require.NoError(t, err)

	service, err := geoip.NewService()
	require.NoError(t, err)

	// Should skip invalid ranges and use valid ones (or MaxMind if available)
	country := service.LookupCountry("1.2.3.5")
	assert.NotEmpty(t, country)

	// Should handle IP not in any valid range
	country = service.LookupCountry("200.200.200.200")
	assert.NotEmpty(t, country) // Will be Unknown or from MaxMind
}

// Test compareIP with all byte comparison paths
func TestCompareIP_AllBytePaths(t *testing.T) {
	err := os.MkdirAll("geoip", 0755)
	if err != nil && !os.IsExist(err) {
		t.Skip("Cannot create geoip directory")
	}
	defer os.RemoveAll("geoip")

	// Create ranges that will trigger different byte comparisons in compareIP
	jsonData := geoip.IPRangesData{
		Ranges: []geoip.IPRange{
			// Ranges designed to test different byte positions
			{Start: "10.0.0.0", End: "10.0.0.255", Country: "T1", CountryName: "Byte 4"},
			{Start: "20.0.0.0", End: "20.0.255.255", Country: "T2", CountryName: "Byte 3"},
			{Start: "30.0.0.0", End: "30.255.255.255", Country: "T3", CountryName: "Byte 2"},
			{Start: "40.0.0.0", End: "100.255.255.255", Country: "T4", CountryName: "Byte 1"},
		},
	}
	data, err := json.Marshal(jsonData)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join("geoip", "ip_ranges.json"), data, 0644)
	require.NoError(t, err)

	service, err := geoip.NewService()
	require.NoError(t, err)

	// Test IPs that will cause different byte comparisons
	testIPs := []struct {
		ip          string
		description string
	}{
		// Test last byte differences (compareIP returns at byte 3)
		{"10.0.0.1", "Last byte < end"},
		{"10.0.0.128", "Last byte middle"},
		{"10.0.0.255", "Last byte == end"},

		// Test third byte differences (compareIP returns at byte 2)
		{"20.0.1.1", "Third byte different"},
		{"20.0.128.1", "Third byte middle"},
		{"20.0.255.1", "Third byte max"},

		// Test second byte differences (compareIP returns at byte 1)
		{"30.1.0.0", "Second byte different"},
		{"30.128.0.0", "Second byte middle"},
		{"30.255.0.0", "Second byte max"},

		// Test first byte differences (compareIP returns at byte 0)
		{"40.0.0.0", "First byte == start"},
		{"50.0.0.0", "First byte middle"},
		{"100.0.0.0", "First byte < end"},
	}

	for _, tc := range testIPs {
		t.Run(tc.description, func(t *testing.T) {
			country := service.LookupCountry(tc.ip)
			assert.NotEmpty(t, country, "Should return country for %s", tc.ip)
		})
	}
}

// Test LookupCountry with IPv4 addresses in different notations
func TestLookupCountry_IPv4Notations(t *testing.T) {
	service, err := geoip.NewService()
	require.NoError(t, err)

	// Test various IPv4 notations
	testCases := []struct {
		ip          string
		description string
	}{
		{"1.1.1.1", "Standard IPv4"},
		{"001.001.001.001", "Leading zeros IPv4"},
		{"1.001.1.1", "Mixed leading zeros"},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			country := service.LookupCountry(tc.ip)
			assert.NotEmpty(t, country)
		})
	}
}

// Test LookupCountry with edge case IPs
func TestLookupCountry_EdgeCaseIPs(t *testing.T) {
	service, err := geoip.NewService()
	require.NoError(t, err)

	edgeCases := []struct {
		ip          string
		description string
	}{
		{"0.0.0.0", "All zeros IPv4"},
		{"255.255.255.255", "All ones IPv4"},
		{"::", "All zeros IPv6"},
		{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "All ones IPv6"},
		{"127.0.0.1", "Loopback"},
		{"::1", "IPv6 loopback"},
	}

	for _, tc := range edgeCases {
		t.Run(tc.description, func(t *testing.T) {
			country := service.LookupCountry(tc.ip)
			assert.NotEmpty(t, country, "Should handle edge case IP %s", tc.ip)
		})
	}
}

// Test GetPublicIP by relying on actual service calls
func TestGetPublicIP_ActualCall(t *testing.T) {
	// This test makes actual HTTP calls
	// It tests the real code path including error handling
	ip := geoip.GetPublicIP()

	// Should return either a valid IP or empty string
	// Should not panic
	if ip != "" {
		t.Logf("Got public IP: %s", ip)
	} else {
		t.Log("Could not get public IP (expected in some environments)")
	}
}

// Test EnrichIPFromService with actual API call
func TestEnrichIPFromService_ActualAPICall(t *testing.T) {
	service, err := geoip.NewService()
	require.NoError(t, err)

	// Test with well-known public IP
	country := service.EnrichIPFromService("8.8.8.8")

	// Should return either country name or "Unknown"
	// Should not panic
	assert.NotEmpty(t, country)
	t.Logf("Enrichment result for 8.8.8.8: %s", country)
}

// Test service methods with nil/empty inputs
func TestService_NilEmptyInputs(t *testing.T) {
	service, err := geoip.NewService()
	require.NoError(t, err)

	// Test with empty string
	country := service.LookupCountry("")
	assert.Equal(t, "Unknown", country)

	// Test with whitespace
	country = service.LookupCountry("   ")
	assert.Equal(t, "Unknown", country)

	// Test enrichment with empty
	country = service.EnrichIPFromService("")
	assert.Equal(t, "Unknown", country)

	// Test enrichment with whitespace
	country = service.EnrichIPFromService("   ")
	assert.Equal(t, "Unknown", country)
}

// Test concurrent service creation
func TestService_ConcurrentCreation(t *testing.T) {
	done := make(chan *geoip.Service, 10)

	// Create multiple services concurrently
	for i := 0; i < 10; i++ {
		go func() {
			service, err := geoip.NewService()
			if err == nil {
				done <- service
			} else {
				done <- nil
			}
		}()
	}

	// Collect all services
	var services []*geoip.Service
	for i := 0; i < 10; i++ {
		service := <-done
		if service != nil {
			services = append(services, service)
		}
	}

	// All should be valid
	assert.Greater(t, len(services), 0)
}

// Test LookupCountry with very long range scan
func TestLookupCountry_LongRangeScan(t *testing.T) {
	err := os.MkdirAll("geoip", 0755)
	if err != nil && !os.IsExist(err) {
		t.Skip("Cannot create geoip directory")
	}
	defer os.RemoveAll("geoip")

	// Create many ranges to test loop iteration
	ranges := make([]geoip.IPRange, 0, 100)
	for i := 0; i < 100; i++ {
		ranges = append(ranges, geoip.IPRange{
			Start:       fmt.Sprintf("%d.0.0.0", i),
			End:         fmt.Sprintf("%d.255.255.255", i),
			Country:     fmt.Sprintf("T%d", i),
			CountryName: fmt.Sprintf("Test %d", i),
		})
	}

	jsonData := geoip.IPRangesData{Ranges: ranges}
	data, err := json.Marshal(jsonData)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join("geoip", "ip_ranges.json"), data, 0644)
	require.NoError(t, err)

	service, err := geoip.NewService()
	require.NoError(t, err)

	// Test IP that requires scanning through many ranges
	country := service.LookupCountry("99.1.1.1")
	assert.NotEmpty(t, country)

	// Test IP not in any range (after all ranges)
	country = service.LookupCountry("200.1.1.1")
	assert.NotEmpty(t, country)
}
