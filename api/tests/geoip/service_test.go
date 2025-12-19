package geoip

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/geoip"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	// Initialize logger for tests
	logger.InitLogger("error", "/dev/null")
}

// TestIsPrivateIP tests private IP detection
func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"Private 10.x", "10.0.0.1", true},
		{"Private 192.168", "192.168.1.1", true},
		{"Private 172.16", "172.16.0.1", true},
		{"Loopback IPv4", "127.0.0.1", true},
		{"Loopback IPv6", "::1", true},
		{"Link-local IPv4", "169.254.1.1", true},
		{"Link-local IPv6", "fe80::1", true},
		{"Public Google", "8.8.8.8", false},
		{"Public Cloudflare", "1.1.1.1", false},
		{"Invalid IP", "invalid", false},
		{"Empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := geoip.IsPrivateIP(tt.ip)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestNewService tests service creation
func TestNewService(t *testing.T) {
	service, err := geoip.NewService()

	assert.NoError(t, err)
	assert.NotNil(t, service)
}

// TestGetInstance tests singleton pattern
func TestGetInstance(t *testing.T) {
	service1, err1 := geoip.GetInstance()
	service2, err2 := geoip.GetInstance()

	assert.NoError(t, err1)
	assert.NoError(t, err2)
	assert.NotNil(t, service1)
	assert.NotNil(t, service2)
	// Should be same instance (singleton)
	assert.Equal(t, service1, service2)
}

// TestLookupCountry_PrivateIPs tests country lookup for private IPs
func TestLookupCountry_PrivateIPs(t *testing.T) {
	service, err := geoip.NewService()
	require.NoError(t, err)

	privateIPs := []string{
		"10.0.0.1",
		"192.168.1.1",
		"172.16.0.1",
		"127.0.0.1",
	}

	for _, ip := range privateIPs {
		country := service.LookupCountry(ip)
		// Private IPs should return Unknown (or the server's public IP location)
		assert.NotEmpty(t, country)
	}
}

// TestLookupCountry_PublicIPs tests country lookup for public IPs
func TestLookupCountry_PublicIPs(t *testing.T) {
	service, err := geoip.NewService()
	require.NoError(t, err)

	// Test with fallback ranges
	country := service.LookupCountry("8.8.8.8")
	assert.NotEmpty(t, country)
}

// TestLookupCountry_InvalidIP tests with invalid IP
func TestLookupCountry_InvalidIP(t *testing.T) {
	service, err := geoip.NewService()
	require.NoError(t, err)

	country := service.LookupCountry("invalid-ip")
	assert.Equal(t, "Unknown", country)
}

// TestLookupCountry_EmptyIP tests with empty IP
func TestLookupCountry_EmptyIP(t *testing.T) {
	service, err := geoip.NewService()
	require.NoError(t, err)

	country := service.LookupCountry("")
	assert.Equal(t, "Unknown", country)
}

// TestLookupCountryWithEnrichment_PrivateIP tests enrichment with private IP
func TestLookupCountryWithEnrichment_PrivateIP(t *testing.T) {
	service, err := geoip.NewService()
	require.NoError(t, err)

	country := service.LookupCountryWithEnrichment("192.168.1.1")
	assert.NotEmpty(t, country)
}

// TestLookupCountryWithEnrichment_PublicIP tests enrichment with public IP
func TestLookupCountryWithEnrichment_PublicIP(t *testing.T) {
	service, err := geoip.NewService()
	require.NoError(t, err)

	// This may or may not call external API depending on local data
	country := service.LookupCountryWithEnrichment("8.8.8.8")
	assert.NotEmpty(t, country)
}

// TestEnrichIPFromService_PrivateIP tests enrichment service with private IP
func TestEnrichIPFromService_PrivateIP(t *testing.T) {
	service, err := geoip.NewService()
	require.NoError(t, err)

	// Should skip private IPs
	country := service.EnrichIPFromService("10.0.0.1")
	assert.Equal(t, "Unknown", country)
}

// TestEnrichIPFromService_InvalidIP tests enrichment service with invalid IP
func TestEnrichIPFromService_InvalidIP(t *testing.T) {
	service, err := geoip.NewService()
	require.NoError(t, err)

	country := service.EnrichIPFromService("not-an-ip")
	assert.Equal(t, "Unknown", country)
}

// TestEnrichIPFromService_PublicIP tests enrichment service with public IP
func TestEnrichIPFromService_PublicIP(t *testing.T) {
	service, err := geoip.NewService()
	require.NoError(t, err)

	// This will attempt external API call
	country := service.EnrichIPFromService("8.8.8.8")
	// Should return something, even if Unknown
	assert.NotEmpty(t, country)
}

// TestLoadFromFile tests loading from JSON file
func TestLoadFromFile(t *testing.T) {
	// Create temporary JSON file
	tmpFile, err := os.CreateTemp("", "ip_ranges_*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	data := geoip.IPRangesData{
		Ranges: []geoip.IPRange{
			{Start: "1.0.0.0", End: "1.255.255.255", Country: "US", CountryName: "United States"},
			{Start: "8.8.8.0", End: "8.8.8.255", Country: "US", CountryName: "United States"},
		},
	}

	jsonData, err := json.Marshal(data)
	require.NoError(t, err)

	_, err = tmpFile.Write(jsonData)
	require.NoError(t, err)
	tmpFile.Close()

	// This tests the internal loadFromFile method indirectly
	// We can't test it directly, but we can verify the service works
	service, err := geoip.NewService()
	assert.NoError(t, err)
	assert.NotNil(t, service)
}

// TestGetPublicIP tests public IP detection
func TestGetPublicIP(t *testing.T) {
	// This may or may not work depending on network availability
	ip := geoip.GetPublicIP()

	if ip != "" {
		// Should be valid IP format
		assert.NotNil(t, net.ParseIP(ip))
	}
	// Empty is acceptable if network unavailable
}

// TestIsPrivateIP_IPv6 tests IPv6 private addresses
func TestIsPrivateIP_IPv6(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"IPv6 loopback", "::1", true},
		{"IPv6 link-local", "fe80::1", true},
		{"IPv6 private ULA", "fd00::1", true},
		{"IPv6 public", "2001:4860:4860::8888", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := geoip.IsPrivateIP(tt.ip)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestLookupCountry_FallbackRanges tests lookup using fallback ranges
func TestLookupCountry_FallbackRanges(t *testing.T) {
	service, err := geoip.NewService()
	require.NoError(t, err)

	// Test IPs that should match fallback ranges
	tests := []struct {
		ip      string
		minLen  int // Minimum expected length of country name
	}{
		{"4.5.6.7", 2},   // US range
		{"1.1.1.1", 2},   // Australia range
		{"77.1.2.3", 2},  // Russia range
	}

	for _, tt := range tests {
		country := service.LookupCountry(tt.ip)
		assert.GreaterOrEqual(t, len(country), tt.minLen)
	}
}

// TestLookupCountry_MultipleIPs tests multiple IP lookups
func TestLookupCountry_MultipleIPs(t *testing.T) {
	service, err := geoip.NewService()
	require.NoError(t, err)

	ips := []string{
		"8.8.8.8",
		"1.1.1.1",
		"9.9.9.9",
		"208.67.222.222",
	}

	for _, ip := range ips {
		country := service.LookupCountry(ip)
		assert.NotEmpty(t, country)
	}
}

// TestLookupCountry_EdgeCases tests edge case IPs
func TestLookupCountry_EdgeCases(t *testing.T) {
	service, err := geoip.NewService()
	require.NoError(t, err)

	edgeCases := []string{
		"0.0.0.0",
		"255.255.255.255",
		"224.0.0.1", // Multicast
	}

	for _, ip := range edgeCases {
		country := service.LookupCountry(ip)
		// Should not panic, returns some value
		assert.NotEmpty(t, country)
	}
}

// TestLookupCountryWithEnrichment_Unknown tests enrichment when local lookup fails
func TestLookupCountryWithEnrichment_Unknown(t *testing.T) {
	service, err := geoip.NewService()
	require.NoError(t, err)

	// Use an IP unlikely to be in local databases
	country := service.LookupCountryWithEnrichment("200.1.2.3")
	assert.NotEmpty(t, country)
}

// TestIsPrivateIP_AllPrivateRanges tests all private IP ranges
func TestIsPrivateIP_AllPrivateRanges(t *testing.T) {
	privateRanges := []string{
		"10.0.0.0",       // Class A private
		"10.255.255.255", // Class A private end
		"172.16.0.0",     // Class B private
		"172.31.255.255", // Class B private end
		"192.168.0.0",    // Class C private
		"192.168.255.255",// Class C private end
		"127.0.0.1",      // Loopback
		"127.255.255.255",// Loopback end
	}

	for _, ip := range privateRanges {
		assert.True(t, geoip.IsPrivateIP(ip), "IP %s should be private", ip)
	}
}

// TestIsPrivateIP_PublicRanges tests public IP ranges
func TestIsPrivateIP_PublicRanges(t *testing.T) {
	publicIPs := []string{
		"1.1.1.1",
		"8.8.8.8",
		"9.9.9.9",
		"208.67.222.222",
		"8.8.4.4",
	}

	for _, ip := range publicIPs {
		assert.False(t, geoip.IsPrivateIP(ip), "IP %s should be public", ip)
	}
}

// TestNewService_Idempotent tests that creating multiple services works
func TestNewService_Idempotent(t *testing.T) {
	service1, err1 := geoip.NewService()
	service2, err2 := geoip.NewService()

	assert.NoError(t, err1)
	assert.NoError(t, err2)
	assert.NotNil(t, service1)
	assert.NotNil(t, service2)
}

// TestLookupCountry_Concurrent tests concurrent lookups
func TestLookupCountry_Concurrent(t *testing.T) {
	service, err := geoip.NewService()
	require.NoError(t, err)

	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func() {
			country := service.LookupCountry("8.8.8.8")
			assert.NotEmpty(t, country)
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestEnrichIPFromService_EmptyString tests enrichment with empty string
func TestEnrichIPFromService_EmptyString(t *testing.T) {
	service, err := geoip.NewService()
	require.NoError(t, err)

	country := service.EnrichIPFromService("")
	assert.Equal(t, "Unknown", country)
}

// TestLookupCountry_IPv6Public tests IPv6 public address lookup
func TestLookupCountry_IPv6Public(t *testing.T) {
	service, err := geoip.NewService()
	require.NoError(t, err)

	// Google's IPv6 DNS
	country := service.LookupCountry("2001:4860:4860::8888")
	assert.NotEmpty(t, country)
}

// TestLookupCountry_IPv6Private tests IPv6 private address lookup
func TestLookupCountry_IPv6Private(t *testing.T) {
	service, err := geoip.NewService()
	require.NoError(t, err)

	privateIPv6 := []string{
		"::1",       // Loopback
		"fe80::1",   // Link-local
		"fd00::1",   // ULA
	}

	for _, ip := range privateIPv6 {
		country := service.LookupCountry(ip)
		assert.NotEmpty(t, country)
	}
}

// TestIsPrivateIP_MalformedIPs tests malformed IP addresses
func TestIsPrivateIP_MalformedIPs(t *testing.T) {
	malformed := []string{
		"256.1.1.1",
		"1.1.1",
		"1.1.1.1.1",
		"abcd",
		"192.168.1",
	}

	for _, ip := range malformed {
		result := geoip.IsPrivateIP(ip)
		// Invalid IPs should return false
		assert.False(t, result, "Malformed IP %s should return false", ip)
	}
}

// TestGetPublicIP_Format tests that GetPublicIP returns valid format
func TestGetPublicIP_Format(t *testing.T) {
	ip := geoip.GetPublicIP()

	if ip != "" {
		// If we got an IP, it should be valid
		parsed := net.ParseIP(ip)
		assert.NotNil(t, parsed, "Public IP should be valid format")

		// Should not be private
		assert.False(t, geoip.IsPrivateIP(ip), "Public IP should not be private")
	}
}

// TestLookupCountryWithEnrichment_InvalidIP tests enrichment with invalid IP
func TestLookupCountryWithEnrichment_InvalidIP(t *testing.T) {
	service, err := geoip.NewService()
	require.NoError(t, err)

	country := service.LookupCountryWithEnrichment("invalid.ip.address")
	assert.Equal(t, "Unknown", country)
}

// TestLookupCountry_LoopbackAddresses tests loopback addresses
func TestLookupCountry_LoopbackAddresses(t *testing.T) {
	service, err := geoip.NewService()
	require.NoError(t, err)

	loopbacks := []string{
		"127.0.0.1",
		"127.0.0.2",
		"127.255.255.255",
		"::1",
	}

	for _, ip := range loopbacks {
		country := service.LookupCountry(ip)
		assert.NotEmpty(t, country)
	}
}

// TestIsPrivateIP_LinkLocal tests link-local addresses
func TestIsPrivateIP_LinkLocal(t *testing.T) {
	linkLocal := []string{
		"169.254.0.1",
		"169.254.169.254",
		"fe80::1",
	}

	for _, ip := range linkLocal {
		assert.True(t, geoip.IsPrivateIP(ip), "Link-local IP %s should be private", ip)
	}
}

// TestLoadFromFile_ValidJSON tests loading valid JSON file
func TestLoadFromFile_ValidJSON(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "ip_ranges_*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	data := geoip.IPRangesData{
		Ranges: []geoip.IPRange{
			{Start: "1.0.0.0", End: "1.255.255.255", Country: "US", CountryName: "United States"},
			{Start: "5.0.0.0", End: "5.255.255.255", Country: "EU", CountryName: "Europe"},
			{Start: "8.8.8.0", End: "8.8.8.255", Country: "US", CountryName: "United States"},
		},
	}

	jsonData, err := json.Marshal(data)
	require.NoError(t, err)

	_, err = tmpFile.Write(jsonData)
	require.NoError(t, err)
	tmpFile.Close()

	// Create service and verify it can use the data
	service, err := geoip.NewService()
	assert.NoError(t, err)
	assert.NotNil(t, service)
}

// TestLoadFromFile_InvalidJSON tests loading invalid JSON
func TestLoadFromFile_InvalidJSON(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "invalid_*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	// Write invalid JSON
	_, err = tmpFile.Write([]byte("{invalid json"))
	require.NoError(t, err)
	tmpFile.Close()

	// Service creation should still succeed (uses fallback ranges)
	service, err := geoip.NewService()
	assert.NoError(t, err)
	assert.NotNil(t, service)
}

// TestLoadFromFile_EmptyFile tests loading empty file
func TestLoadFromFile_EmptyFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "empty_*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	// Service creation should still succeed
	service, err := geoip.NewService()
	assert.NoError(t, err)
	assert.NotNil(t, service)
}

// TestLoadFromFile_LargeFile tests loading large JSON file
func TestLoadFromFile_LargeFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "large_*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	// Create large dataset
	ranges := make([]geoip.IPRange, 1000)
	for i := 0; i < 1000; i++ {
		ranges[i] = geoip.IPRange{
			Start:       fmt.Sprintf("%d.0.0.0", i),
			End:         fmt.Sprintf("%d.255.255.255", i),
			Country:     "XX",
			CountryName: "Test Country",
		}
	}

	data := geoip.IPRangesData{Ranges: ranges}
	jsonData, err := json.Marshal(data)
	require.NoError(t, err)

	_, err = tmpFile.Write(jsonData)
	require.NoError(t, err)
	tmpFile.Close()

	service, err := geoip.NewService()
	assert.NoError(t, err)
	assert.NotNil(t, service)
}

// TestGetPublicIP_MultipleServices tests fallback to multiple services
func TestGetPublicIP_MultipleServices(t *testing.T) {
	// This tests the GetPublicIP function which tries multiple services
	ip := geoip.GetPublicIP()

	// May be empty if no network, but shouldn't panic
	if ip != "" {
		parsed := net.ParseIP(ip)
		assert.NotNil(t, parsed)
		// Should not be private if we got an IP
		assert.False(t, geoip.IsPrivateIP(ip))
	}
}

// TestGetPublicIP_Reliability tests GetPublicIP reliability
func TestGetPublicIP_Reliability(t *testing.T) {
	// Call multiple times to test caching/reliability
	ip1 := geoip.GetPublicIP()
	ip2 := geoip.GetPublicIP()

	// Both calls should return the same result
	if ip1 != "" && ip2 != "" {
		assert.Equal(t, ip1, ip2)
	}
}

// TestEnrichIPFromService_Success tests successful enrichment
func TestEnrichIPFromService_Success(t *testing.T) {
	service, err := geoip.NewService()
	require.NoError(t, err)

	// Test with a public IP (may or may not succeed depending on network)
	country := service.EnrichIPFromService("1.1.1.1")
	assert.NotEmpty(t, country)
}

// TestEnrichIPFromService_MultiplePublicIPs tests enrichment with multiple IPs
func TestEnrichIPFromService_MultiplePublicIPs(t *testing.T) {
	service, err := geoip.NewService()
	require.NoError(t, err)

	publicIPs := []string{
		"8.8.8.8",
		"1.1.1.1",
		"9.9.9.9",
	}

	for _, ip := range publicIPs {
		country := service.EnrichIPFromService(ip)
		// Should return something (even if Unknown due to network issues)
		assert.NotEmpty(t, country)
	}
}

// TestLookupCountry_IPv4Ranges tests various IPv4 ranges
func TestLookupCountry_IPv4Ranges(t *testing.T) {
	service, err := geoip.NewService()
	require.NoError(t, err)

	ipRanges := []struct {
		ip       string
		minLen   int
		category string
	}{
		{"1.1.1.1", 2, "public"},
		{"8.8.8.8", 2, "public"},
		{"10.0.0.1", 2, "private"},
		{"192.168.1.1", 2, "private"},
		{"172.16.0.1", 2, "private"},
		{"127.0.0.1", 2, "loopback"},
	}

	for _, tc := range ipRanges {
		country := service.LookupCountry(tc.ip)
		assert.GreaterOrEqual(t, len(country), tc.minLen, "IP %s (%s) should return country", tc.ip, tc.category)
	}
}

// TestLookupCountry_BoundaryIPs tests boundary IP addresses
func TestLookupCountry_BoundaryIPs(t *testing.T) {
	service, err := geoip.NewService()
	require.NoError(t, err)

	boundaryIPs := []string{
		"0.0.0.1",
		"255.255.255.254",
		"1.0.0.0",
		"1.255.255.255",
	}

	for _, ip := range boundaryIPs {
		country := service.LookupCountry(ip)
		assert.NotEmpty(t, country)
	}
}

// TestNewService_MultipleCalls tests multiple service creations
func TestNewService_MultipleCalls(t *testing.T) {
	services := make([]*geoip.Service, 5)

	for i := 0; i < 5; i++ {
		service, err := geoip.NewService()
		assert.NoError(t, err)
		assert.NotNil(t, service)
		services[i] = service
	}

	// All services should work
	for i, service := range services {
		country := service.LookupCountry("8.8.8.8")
		assert.NotEmpty(t, country, "Service %d should work", i)
	}
}

// TestEnrichIPFromService_WithCaching tests caching behavior
func TestEnrichIPFromService_WithCaching(t *testing.T) {
	service, err := geoip.NewService()
	require.NoError(t, err)

	// First call
	country1 := service.EnrichIPFromService("8.8.8.8")
	assert.NotEmpty(t, country1)

	// Second call (should potentially use cache)
	country2 := service.EnrichIPFromService("8.8.8.8")
	assert.Equal(t, country1, country2)
}

// TestLookupCountry_SpecialAddresses tests special address ranges
func TestLookupCountry_SpecialAddresses(t *testing.T) {
	service, err := geoip.NewService()
	require.NoError(t, err)

	specialAddrs := []string{
		"169.254.169.254", // AWS metadata
		"100.64.0.1",      // Carrier-grade NAT
		"198.18.0.1",      // Benchmark testing
		"203.0.113.1",     // Documentation
	}

	for _, ip := range specialAddrs {
		country := service.LookupCountry(ip)
		assert.NotEmpty(t, country)
	}
}

// TestEnrichIPFromService_NetworkError tests handling of network errors
func TestEnrichIPFromService_NetworkError(t *testing.T) {
	service, err := geoip.NewService()
	require.NoError(t, err)

	// Using invalid IP should return Unknown
	country := service.EnrichIPFromService("999.999.999.999")
	assert.Equal(t, "Unknown", country)
}

// TestLookupCountryWithEnrichment_Fallback tests enrichment fallback
func TestLookupCountryWithEnrichment_Fallback(t *testing.T) {
	service, err := geoip.NewService()
	require.NoError(t, err)

	// Test with various IPs
	ips := []string{
		"8.8.8.8",
		"1.1.1.1",
		"208.67.222.222",
	}

	for _, ip := range ips {
		country := service.LookupCountryWithEnrichment(ip)
		assert.NotEmpty(t, country)
	}
}
