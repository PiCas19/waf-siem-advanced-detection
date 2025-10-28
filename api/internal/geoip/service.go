package geoip

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"

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
	reader *geoip2.Reader
	ranges []IPRange
	mu     sync.RWMutex
}

var instance *Service
var once sync.Once

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
		ranges: []IPRange{},
	}

	// Try to load MaxMind GeoLite2 database
	if reader, err := geoip2.Open("geoip/GeoLite2-Country.mmdb"); err == nil {
		s.reader = reader
		fmt.Println("[INFO] MaxMind GeoLite2 database loaded successfully")
		return s, nil
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

// LookupCountry returns country name for given IP address
func (s *Service) LookupCountry(ipStr string) string {
	s.mu.RLock()
	reader := s.reader
	ranges := s.ranges
	s.mu.RUnlock()

	// Try MaxMind first if available
	if reader != nil {
		ip := net.ParseIP(ipStr)
		if ip != nil {
			record, err := reader.Country(ip)
			if err == nil && record != nil && record.Country.IsoCode != "" {
				return record.Country.Names["en"]
			}
		}
	}

	// Fallback to JSON ranges
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "Unknown"
	}

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

// getFallbackRanges returns hardcoded ranges for fallback
func getFallbackRanges() []IPRange {
	return []IPRange{
		{Start: "1.0.0.0", End: "1.255.255.255", Country: "AU", CountryName: "Australia"},
		{Start: "4.0.0.0", End: "4.255.255.255", Country: "US", CountryName: "United States"},
		{Start: "7.0.0.0", End: "7.255.255.255", Country: "RU", CountryName: "Russia"},
		{Start: "16.0.0.0", End: "16.255.255.255", Country: "CN", CountryName: "China"},
		{Start: "17.0.0.0", End: "17.255.255.255", Country: "BR", CountryName: "Brazil"},
		{Start: "37.0.0.0", End: "37.255.255.255", Country: "RU", CountryName: "Russia"},
		{Start: "77.0.0.0", End: "77.255.255.255", Country: "RU", CountryName: "Russia"},
	}
}
