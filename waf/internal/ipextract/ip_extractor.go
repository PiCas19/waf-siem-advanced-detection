package ipextract

import (
	"net"
	"net/http"
	"strings"
	"time"
)

// ClientIPSource represents the source from which the client IP was extracted
type ClientIPSource string

const (
	SourceXPublicIP    ClientIPSource = "x-public-ip"      // Client-reported public IP (Tailscale/VPN)
	SourceXForwardedFor ClientIPSource = "x-forwarded-for"  // From trusted proxy chain
	SourceXRealIP      ClientIPSource = "x-real-ip"        // From trusted reverse proxy
	SourceRemoteAddr   ClientIPSource = "remote-addr"      // Direct connection IP
)

// ClientIPInfo contains the extracted IP and metadata about how it was extracted
type ClientIPInfo struct {
	IP            string        // The extracted IP address
	Source        ClientIPSource // Where the IP came from
	IsTrusted     bool          // Whether the source is considered trustworthy
	IsPublicIP    bool          // Whether it's a public/external IP
	IsPrivateIP   bool          // Whether it's a private/internal IP
	IsVPNTailscale bool          // Whether it was reported via X-Public-IP (implies Tailscale/VPN)
}

// TrustedProxies holds a list of trusted proxy IPs
// In production, this should be configurable and match your reverse proxy setup
var TrustedProxies = []string{
	"127.0.0.1",
	"::1",
	"localhost",
	// Common reverse proxy IPs - configure these based on your infrastructure
	// "10.0.0.0/8",        // Docker/private networks
	// "172.16.0.0/12",     // Docker networks
	// "192.168.0.0/16",    // Private networks
}

// SetTrustedProxies configures the list of trusted proxy IP addresses
// This should be called during initialization with IPs of your reverse proxies
func SetTrustedProxies(proxies []string) {
	TrustedProxies = proxies
}

// AddTrustedProxy adds a single proxy IP to the trusted list
func AddTrustedProxy(proxyIP string) {
	TrustedProxies = append(TrustedProxies, proxyIP)
}

// isTrustedProxy checks if an IP is in the trusted proxy list
func isTrustedProxy(ip string) bool {
	for _, proxy := range TrustedProxies {
		if strings.EqualFold(ip, proxy) {
			return true
		}
		// Check CIDR notation
		if _, ipnet, err := net.ParseCIDR(proxy); err == nil {
			if ipnet.Contains(net.ParseIP(ip)) {
				return true
			}
		}
	}
	return false
}

// isPublicIP checks if an IP address is public (not private/reserved)
func isPublicIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// Check for private ranges
	if parsedIP.IsPrivate() {
		return false
	}

	// Check for loopback
	if parsedIP.IsLoopback() {
		return false
	}

	// Check for link-local
	if parsedIP.IsLinkLocalUnicast() {
		return false
	}

	// Check for multicast
	if parsedIP.IsMulticast() {
		return false
	}

	// Check for unspecified (0.0.0.0 or ::)
	if parsedIP.IsUnspecified() {
		return false
	}

	return true
}

// isPrivateIP checks if an IP address is private
func isPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	return parsedIP.IsPrivate()
}

// ExtractClientIP extracts the client IP using a robust multi-step process
// Priority order:
// 1. X-Public-IP header (client-reported, used by Tailscale/VPN clients)
// 2. X-Forwarded-For header (only if from trusted proxy)
// 3. X-Real-IP header (only if from trusted proxy)
// 4. RemoteAddr (direct connection)
func ExtractClientIP(
	xPublicIP string,
	xForwardedFor string,
	xRealIP string,
	remoteAddr string,
	sourceIP string,
) *ClientIPInfo {
	// Step 1: Check X-Public-IP header (client-reported public IP)
	// This is useful for Tailscale/VPN users who want to report their real public IP
	if xPublicIP != "" {
		xPublicIP = strings.TrimSpace(xPublicIP)
		if isValidIP(xPublicIP) {
			return &ClientIPInfo{
				IP:             xPublicIP,
				Source:         SourceXPublicIP,
				IsTrusted:      true, // Client explicitly reports it
				IsPublicIP:     isPublicIP(xPublicIP),
				IsPrivateIP:    isPrivateIP(xPublicIP),
				IsVPNTailscale: true,
			}
		}
	}

	// Step 2: Check X-Forwarded-For header (proxy chain)
	// Only use if the request comes from a trusted proxy
	if xForwardedFor != "" && isTrustedProxy(sourceIP) {
		ips := strings.Split(xForwardedFor, ",")
		for _, ip := range ips {
			ip = strings.TrimSpace(ip)
			if isValidIP(ip) {
				return &ClientIPInfo{
					IP:             ip,
					Source:         SourceXForwardedFor,
					IsTrusted:      true,
					IsPublicIP:     isPublicIP(ip),
					IsPrivateIP:    isPrivateIP(ip),
					IsVPNTailscale: false,
				}
			}
		}
	}

	// Step 3: Check X-Real-IP header (nginx reverse proxy)
	// Only use if the request comes from a trusted proxy
	if xRealIP != "" && isTrustedProxy(sourceIP) {
		xRealIP = strings.TrimSpace(xRealIP)
		if isValidIP(xRealIP) {
			return &ClientIPInfo{
				IP:             xRealIP,
				Source:         SourceXRealIP,
				IsTrusted:      true,
				IsPublicIP:     isPublicIP(xRealIP),
				IsPrivateIP:    isPrivateIP(xRealIP),
				IsVPNTailscale: false,
			}
		}
	}

	// Step 4: Use RemoteAddr as fallback (direct connection)
	remoteAddr = strings.TrimSpace(remoteAddr)
	if remoteAddr != "" {
		// Extract just the IP from "IP:port" format
		ip := extractIPFromRemoteAddr(remoteAddr)
		if ip != "" && isValidIP(ip) {
			return &ClientIPInfo{
				IP:             ip,
				Source:         SourceRemoteAddr,
				IsTrusted:      true, // Direct connection is always trustworthy
				IsPublicIP:     isPublicIP(ip),
				IsPrivateIP:    isPrivateIP(ip),
				IsVPNTailscale: false,
			}
		}
	}

	// Fallback: return unknown IP
	return &ClientIPInfo{
		IP:             "0.0.0.0",
		Source:         SourceRemoteAddr,
		IsTrusted:      false,
		IsPublicIP:     false,
		IsPrivateIP:    false,
		IsVPNTailscale: false,
	}
}

// ExtractClientIPFromHeaders is a convenience function that takes HTTP headers
// and extracts the client IP using the robust extraction logic
func ExtractClientIPFromHeaders(
	xPublicIP string,
	xForwardedFor string,
	xRealIP string,
	remoteAddr string,
) *ClientIPInfo {
	// Extract the source IP from RemoteAddr to check if it's a trusted proxy
	sourceIP := extractIPFromRemoteAddr(remoteAddr)
	return ExtractClientIP(xPublicIP, xForwardedFor, xRealIP, remoteAddr, sourceIP)
}

// ExtractClientIPSimple is the simple version that just returns the IP string
// This is useful for backward compatibility
func ExtractClientIPSimple(
	xPublicIP string,
	xForwardedFor string,
	xRealIP string,
	remoteAddr string,
) string {
	info := ExtractClientIPFromHeaders(xPublicIP, xForwardedFor, xRealIP, remoteAddr)
	return info.IP
}

// extractIPFromRemoteAddr extracts just the IP part from "IP:port" format
func extractIPFromRemoteAddr(remoteAddr string) string {
	if remoteAddr == "" {
		return ""
	}

	// Check if it's an IPv6 address (contains multiple colons)
	if strings.Count(remoteAddr, ":") > 1 {
		// IPv6 - format is [::1]:port or similar
		if idx := strings.LastIndex(remoteAddr, ":"); idx != -1 {
			host := remoteAddr[:idx]
			// Remove brackets if present
			host = strings.TrimPrefix(host, "[")
			host = strings.TrimSuffix(host, "]")
			return host
		}
	}

	// IPv4 - format is 192.168.1.1:port
	if idx := strings.LastIndex(remoteAddr, ":"); idx != -1 {
		return remoteAddr[:idx]
	}

	// No port separator found, assume it's just the IP
	return remoteAddr
}

// isValidIP checks if a string is a valid IP address (v4 or v6)
func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// IsIPInRange checks if an IP is within a CIDR range
func IsIPInRange(ip, cidr string) bool {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return ipnet.Contains(net.ParseIP(ip))
}

// GetIPType returns a human-readable description of the IP type
func GetIPType(ip string) string {
	if !isValidIP(ip) {
		return "invalid"
	}

	parsedIP := net.ParseIP(ip)

	if parsedIP.IsLoopback() {
		return "loopback"
	}
	if parsedIP.IsPrivate() {
		return "private"
	}
	if parsedIP.IsLinkLocalUnicast() {
		return "link-local"
	}
	if parsedIP.IsMulticast() {
		return "multicast"
	}
	if parsedIP.IsUnspecified() {
		return "unspecified"
	}

	return "public"
}

// ExtractClientIPWithPolicy estrae l'IP del client applicando una policy di trusted sources
// Questo è il metodo enterprise-grade che integra signature validation + source policy
func ExtractClientIPWithPolicy(
	r *http.Request,
	remoteAddr string,
	manager *GlobalTrustedSourceManager,
	sigConfig *HeaderSignatureConfig,
	dmzConfig *DMZDetectionConfig,
	tsConfig *TailscaleDetectionConfig,
) *EnhancedClientIPInfo {
	// Prima estrai l'IP usando la logica standard
	basicInfo := ExtractClientIPFromHeaders(
		r.Header.Get("X-Public-IP"),
		r.Header.Get("X-Forwarded-For"),
		r.Header.Get("X-Real-IP"),
		remoteAddr,
	)

	// Estrai source IP
	sourceIP := extractIPFromRemoteAddr(remoteAddr)

	// Valida la firma se X-Public-IP è presente
	headerSigValid := false
	if r.Header.Get("X-Public-IP") != "" && sigConfig.Enabled {
		result := ValidateHeaderSignature(r, sigConfig, sourceIP)
		headerSigValid = result.IsValid
	}

	// Controlla se è DMZ
	isDMZ := IsDMZIP(basicInfo.IP, dmzConfig)

	// Controlla se è Tailscale
	isTailscale := IsTailscaleIP(basicInfo.IP, tsConfig)

	// Determina il source type
	sourceType := "unknown"
	if isDMZ {
		sourceType = "dmz"
	} else if isTailscale {
		sourceType = "tailscale"
	} else if basicInfo.IsPublicIP {
		sourceType = "public"
	} else if basicInfo.IsPrivateIP {
		sourceType = "private"
	}

	// Calcola trust score
	isWhitelisted := false // Questo verrà impostato dal middleware
	trustScore := ComputeTrustScore(basicInfo, headerSigValid, isDMZ, isTailscale, isWhitelisted)

	// Determina classificazione
	classification := "untrusted"
	if manager != nil && manager.IsTrusted(sourceIP) {
		classification = "trusted"
	} else if trustScore >= 75 {
		classification = "trusted"
	} else if trustScore >= 50 {
		classification = "neutral"
	}

	enhanced := &EnhancedClientIPInfo{
		ClientIPInfo:         basicInfo,
		SourceType:           sourceType,
		SourceClassification: classification,
		HeaderSignatureValid: headerSigValid,
		DMZIP:                isDMZ,
		TailscaleIP:          isTailscale,
		TrustScore:           trustScore,
		ValidationTimestamp:  time.Now(),
	}

	// Aggiungi dettagli di validazione
	if basicInfo.Source == SourceXPublicIP {
		enhanced.ValidationDetails = "Client-reported public IP"
		if headerSigValid {
			enhanced.ValidationDetails += " [HMAC signed]"
		} else if sigConfig.Enabled {
			enhanced.ValidationDetails += " [SIGNATURE INVALID]"
		}
	}

	return enhanced
}

// Aggiungi import per http e time se non presenti
// (già presenti nel package, ma documentiamo qui per chiarezza)
// import (
//     "net/http"
//     "time"
// )
