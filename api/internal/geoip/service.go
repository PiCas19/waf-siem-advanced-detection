package geoip

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
)

type IPRange struct {
	Start       string `json:"start"`
	End         string `json:"end"`
	Country     string `json:"country"`
	CountryName string `json:"country_name"`
}

type IPRangesData struct {
	Ranges []IPRange `json:"ranges"`
}

type Service struct {
	reader      *geoip2.Reader
	ranges      []IPRange
	publicIP    string
	mu          sync.RWMutex
}

var instance *Service
var once sync.Once

// GetPublicIP retrieves the server's public IP address
// Tries multiple free services for redundancy
func GetPublicIP() string {
	services := []string{
		"https://api.ipify.org?format=text",
		"https://checkip.amazonaws.com",
		"https://icanhazip.com",
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	for _, service := range services {
		resp, err := client.Get(service)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		ip := strings.TrimSpace(string(body))
		if net.ParseIP(ip) != nil {
			return ip
		}
	}

	fmt.Println("[WARN] Could not detect server public IP, local IP mapping will not work")
	return ""
}

// GetInstance returns singleton instance of GeoIP service
func GetInstance() (*Service, error) {
	var err error
	once.Do(func() {
		instance, err = NewService()
	})
	return instance, err
}

// NewService loads MaxMind database if available, otherwise uses JSON fallback
func NewService() (*Service, error) {
	s := &Service{
		ranges:   []IPRange{},
		publicIP: GetPublicIP(), // Detect server's public IP for local IP mapping
	}

	// Try to load MaxMind GeoLite2 database
	dbPaths := []string{
		"geoip/GeoLite2-Country.mmdb",
		"./geoip/GeoLite2-Country.mmdb",
		"/geoip/GeoLite2-Country.mmdb",
	}

	for _, dbPath := range dbPaths {
		if reader, err := geoip2.Open(dbPath); err == nil {
			s.reader = reader
			return s, nil
		}
	}

	// Fallback to JSON file if MaxMind not available
	fmt.Println("[WARN] MaxMind database not found, falling back to JSON IP ranges")
	if err := s.loadFromFile("geoip/ip_ranges.json"); err != nil {
		// If JSON file also not found, use hardcoded fallback ranges
		fmt.Println("[WARN] Could not load IP ranges from file, using fallback ranges")
		s.ranges = getFallbackRanges()
	}

	return s, nil
}

func (s *Service) loadFromFile(filepath string) error {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return err
	}

	var ipData IPRangesData
	if err := json.Unmarshal(data, &ipData); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.ranges = ipData.Ranges
	return nil
}

// IsPrivateIP checks if IP address is private/local
func IsPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Check loopback (127.0.0.0/8 for IPv4, ::1 for IPv6)
	if ip.IsLoopback() {
		return true
	}

	// Check private ranges
	if ip.IsPrivate() {
		return true
	}

	// Check link-local
	if ip.IsLinkLocalUnicast() {
		return true
	}

	return false
}

// LookupCountry returns country name for given IP address
// For private/local IPs, uses the server's public IP for geolocation
func (s *Service) LookupCountry(ipStr string) string {
	s.mu.RLock()
	reader := s.reader
	ranges := s.ranges
	publicIP := s.publicIP
	s.mu.RUnlock()

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "Unknown"
	}

	// Handle private/local IPs - map to server's public IP location
	if IsPrivateIP(ipStr) {
		if publicIP != "" {
			// Recursively lookup using the public IP
			return s.LookupCountry(publicIP)
		}
		return "Unknown"
	}

	// Try MaxMind first if available
	if reader != nil {
		record, err := reader.Country(ip)
		if err == nil && record != nil && record.Country.IsoCode != "" {
			country := record.Country.Names["en"]
			if country != "" {
				return country
			}
		}
	}

	// Fallback to JSON ranges
	for _, r := range ranges {
		startIP := net.ParseIP(r.Start)
		endIP := net.ParseIP(r.End)

		if startIP == nil || endIP == nil {
			continue
		}

		if ipBetween(ip, startIP, endIP) {
			return r.CountryName
		}
	}

	return "Unknown"
}

// ipBetween checks if ip is between start and end (inclusive)
func ipBetween(ip, start, end net.IP) bool {
	if len(ip) == net.IPv4len {
		ip = ip.To4()
	} else {
		ip = ip.To16()
	}

	if len(start) == net.IPv4len {
		start = start.To4()
	} else {
		start = start.To16()
	}

	if len(end) == net.IPv4len {
		end = end.To4()
	} else {
		end = end.To16()
	}

	return (compareIP(ip, start) >= 0) && (compareIP(ip, end) <= 0)
}

// compareIP compares two IPs (-1 if a < b, 0 if a == b, 1 if a > b)
func compareIP(a, b net.IP) int {
	for i := 0; i < len(a); i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

// IPifyResponse represents the response from ipify.org API
type IPifyResponse struct {
	Query   string `json:"query"`
	Status  string `json:"status"`
	Country string `json:"country"`
	City    string `json:"city"`
	Org     string `json:"org"`
}

// EnrichIPFromService enriches unknown IPs using ipify.org API
// This is called when local databases don't recognize an IP
func (s *Service) EnrichIPFromService(ipStr string) string {
	// Skip private IPs
	if IsPrivateIP(ipStr) {
		return "Unknown"
	}

	// Validate IP format
	if net.ParseIP(ipStr) == nil {
		return "Unknown"
	}

	client := &http.Client{
		Timeout: 3 * time.Second,
	}

	// Use ipapi.co which is free and includes country info
	// Format: https://ipapi.co/{ip}/json/
	url := fmt.Sprintf("https://ipapi.co/%s/json/", ipStr)

	resp, err := client.Get(url)
	if err != nil {
		return "Unknown"
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "Unknown"
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "Unknown"
	}

	var apiResp map[string]interface{}
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return "Unknown"
	}

	// Extract country name from response
	if country, ok := apiResp["country_name"].(string); ok && country != "" {
		return country
	}

	return "Unknown"
}

// LookupCountryWithEnrichment performs country lookup with ipify enrichment fallback
func (s *Service) LookupCountryWithEnrichment(ipStr string) string {
	// First try standard lookup methods
	country := s.LookupCountry(ipStr)
	if country != "Unknown" {
		return country
	}

	// If not found and it's a public IP, try enrichment from ipify service
	if !IsPrivateIP(ipStr) {
		return s.EnrichIPFromService(ipStr)
	}

	return "Unknown"
}

// getFallbackRanges returns hardcoded ranges for fallback
func getFallbackRanges() []IPRange {
	return []IPRange{
		// Switzerland (Lugano area testing)
		{Start: "5.102.0.0", End: "5.102.255.255", Country: "CH", CountryName: "Switzerland"},
		{Start: "78.40.0.0", End: "78.40.255.255", Country: "CH", CountryName: "Switzerland"},
		{Start: "195.0.0.0", End: "195.255.255.255", Country: "CH", CountryName: "Switzerland"},

		// Europe
		{Start: "1.0.0.0", End: "1.255.255.255", Country: "AU", CountryName: "Australia"},
		{Start: "4.0.0.0", End: "4.255.255.255", Country: "US", CountryName: "United States"},
		{Start: "7.0.0.0", End: "7.255.255.255", Country: "RU", CountryName: "Russia"},
		{Start: "16.0.0.0", End: "16.255.255.255", Country: "CN", CountryName: "China"},
		{Start: "17.0.0.0", End: "17.255.255.255", Country: "BR", CountryName: "Brazil"},
		{Start: "37.0.0.0", End: "37.255.255.255", Country: "RU", CountryName: "Russia"},
		{Start: "77.0.0.0", End: "77.255.255.255", Country: "RU", CountryName: "Russia"},
	}
}
