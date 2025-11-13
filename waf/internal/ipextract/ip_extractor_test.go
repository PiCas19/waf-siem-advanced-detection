package ipextract

import (
	"testing"
)

func TestExtractClientIP(t *testing.T) {
	// Reset to default trusted proxies
	TrustedProxies = []string{"127.0.0.1", "::1"}

	tests := []struct {
		name           string
		xPublicIP      string
		xForwardedFor  string
		xRealIP        string
		remoteAddr     string
		sourceIP       string
		expectedIP     string
		expectedSource ClientIPSource
		expectedVPN    bool
	}{
		{
			name:           "X-Public-IP takes priority (Tailscale/VPN)",
			xPublicIP:      "203.0.113.42",
			xForwardedFor:  "192.0.2.1",
			xRealIP:        "192.0.2.2",
			remoteAddr:     "127.0.0.1:8080",
			sourceIP:       "127.0.0.1",
			expectedIP:     "203.0.113.42",
			expectedSource: SourceXPublicIP,
			expectedVPN:    true,
		},
		{
			name:           "X-Forwarded-For from trusted proxy",
			xPublicIP:      "",
			xForwardedFor:  "192.0.2.1, 10.0.0.1",
			xRealIP:        "192.0.2.2",
			remoteAddr:     "127.0.0.1:8080",
			sourceIP:       "127.0.0.1",
			expectedIP:     "192.0.2.1",
			expectedSource: SourceXForwardedFor,
			expectedVPN:    false,
		},
		{
			name:           "X-Real-IP from trusted proxy",
			xPublicIP:      "",
			xForwardedFor:  "",
			xRealIP:        "203.0.113.10",
			remoteAddr:     "127.0.0.1:8080",
			sourceIP:       "127.0.0.1",
			expectedIP:     "203.0.113.10",
			expectedSource: SourceXRealIP,
			expectedVPN:    false,
		},
		{
			name:           "RemoteAddr fallback",
			xPublicIP:      "",
			xForwardedFor:  "",
			xRealIP:        "",
			remoteAddr:     "192.168.1.100:54321",
			sourceIP:       "192.168.1.100",
			expectedIP:     "192.168.1.100",
			expectedSource: SourceRemoteAddr,
			expectedVPN:    false,
		},
		{
			name:           "IPv6 RemoteAddr",
			xPublicIP:      "",
			xForwardedFor:  "",
			xRealIP:        "",
			remoteAddr:     "[2001:db8::1]:8080",
			sourceIP:       "2001:db8::1",
			expectedIP:     "2001:db8::1",
			expectedSource: SourceRemoteAddr,
			expectedVPN:    false,
		},
		{
			name:           "X-Forwarded-For ignored from untrusted proxy",
			xPublicIP:      "",
			xForwardedFor:  "203.0.113.50",
			xRealIP:        "",
			remoteAddr:     "198.51.100.1:8080",
			sourceIP:       "198.51.100.1",
			expectedIP:     "198.51.100.1",
			expectedSource: SourceRemoteAddr,
			expectedVPN:    false,
		},
		{
			name:           "Whitespace trimming",
			xPublicIP:      "",
			xForwardedFor:  "  203.0.113.20  ,  10.0.0.1  ",
			xRealIP:        "",
			remoteAddr:     "127.0.0.1:8080",
			sourceIP:       "127.0.0.1",
			expectedIP:     "203.0.113.20",
			expectedSource: SourceXForwardedFor,
			expectedVPN:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractClientIP(tt.xPublicIP, tt.xForwardedFor, tt.xRealIP, tt.remoteAddr, tt.sourceIP)

			if result.IP != tt.expectedIP {
				t.Errorf("Expected IP %s, got %s", tt.expectedIP, result.IP)
			}

			if result.Source != tt.expectedSource {
				t.Errorf("Expected source %s, got %s", tt.expectedSource, result.Source)
			}

			if result.IsVPNTailscale != tt.expectedVPN {
				t.Errorf("Expected VPN %v, got %v", tt.expectedVPN, result.IsVPNTailscale)
			}
		})
	}
}

func TestIsPublicIP(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"8.8.8.8", true},
		{"203.0.113.1", true},
		{"127.0.0.1", false},
		{"localhost", false},
		{"192.168.1.1", false},
		{"10.0.0.1", false},
		{"172.16.0.1", false},
		{"::1", false},
		{"2001:db8::1", true},
		{"invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			result := isPublicIP(tt.ip)
			if result != tt.expected {
				t.Errorf("Expected %v for %s, got %v", tt.expected, tt.ip, result)
			}
		})
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"8.8.8.8", false},
		{"127.0.0.1", false},
		{"::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			result := isPrivateIP(tt.ip)
			if result != tt.expected {
				t.Errorf("Expected %v for %s, got %v", tt.expected, tt.ip, result)
			}
		})
	}
}

func TestExtractIPFromRemoteAddr(t *testing.T) {
	tests := []struct {
		remoteAddr string
		expected   string
	}{
		{"192.168.1.1:8080", "192.168.1.1"},
		{"127.0.0.1:54321", "127.0.0.1"},
		{"[2001:db8::1]:8080", "2001:db8::1"},
		{"[::1]:3000", "::1"},
		{"192.168.1.1", "192.168.1.1"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.remoteAddr, func(t *testing.T) {
			result := extractIPFromRemoteAddr(tt.remoteAddr)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestTrustedProxyValidation(t *testing.T) {
	// Set custom trusted proxies
	SetTrustedProxies([]string{"10.0.0.1", "192.168.1.0/24"})

	tests := []struct {
		ip       string
		expected bool
	}{
		{"10.0.0.1", true},
		{"192.168.1.1", true},
		{"192.168.1.100", true},
		{"192.168.2.1", false},
		{"8.8.8.8", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			result := isTrustedProxy(tt.ip)
			if result != tt.expected {
				t.Errorf("Expected %v for %s, got %v", tt.expected, tt.ip, result)
			}
		})
	}

	// Reset to default
	TrustedProxies = []string{"127.0.0.1", "::1"}
}

func TestGetIPType(t *testing.T) {
	tests := []struct {
		ip       string
		expected string
	}{
		{"127.0.0.1", "loopback"},
		{"192.168.1.1", "private"},
		{"8.8.8.8", "public"},
		{"::1", "loopback"},
		{"2001:db8::1", "public"},
		{"invalid", "invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			result := GetIPType(tt.ip)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}
