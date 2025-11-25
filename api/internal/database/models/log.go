package models

import "time"

// Log represents a WAF security event with detailed threat intelligence and IP metadata.
//
// Fields:
//   - ID (uint): Primary key identifier for the log entry
//   - CreatedAt (time.Time): Timestamp when the security event occurred
//   - ThreatType (string): Type of threat detected (e.g., "xss", "sqli", "lfi")
//   - Severity (string): Severity level - "low", "medium", "high", or "critical"
//   - Description (string): Human-readable description of the threat
//   - ClientIP (string): IP address of the client (indexed)
//   - Method (string): HTTP method of the request
//   - URL (string): Target URL of the request
//   - UserAgent (string): User agent string from the request
//   - Payload (string): Detected malicious payload or pattern
//   - Blocked (bool): Whether the request was blocked
//   - BlockedBy (string): How the threat was blocked - "auto" (by rule), "manual" (by operator), or "" (not blocked)
//   - ClientIPSource (string): How the IP was extracted - "x-public-ip", "x-forwarded-for", "x-real-ip", "remote-addr"
//   - ClientIPTrusted (bool): Whether the IP source is from a trusted source
//   - ClientIPVPNReport (bool): Whether this is a self-reported IP from Tailscale/VPN client
//   - ClientIPPublic (string): The public IP reported by Tailscale/VPN client (from X-Public-IP header)
//   - IPTrustScore (*int): IP Trust Score (0-100): 0-25=untrusted, 25-50=low, 50-75=neutral, 75-100=trusted
//   - IPReputation (*int): IP reputation score (0-100, higher = more suspicious)
//   - IsMalicious (bool): Whether IP is known to be malicious
//   - ASN (string): Autonomous System Number
//   - ISP (string): Internet Service Provider
//   - Country (string): Country code (ISO 3166-1 alpha-2)
//   - ThreatLevel (string): Threat level - "critical", "high", "medium", "low", "none"
//   - ThreatSource (string): Source of threat intel (e.g., "abuseipdb", "alienvault", "local_rules")
//   - IsOnBlocklist (bool): Whether IP is on known blocklists
//   - BlocklistName (string): Name of blocklist if matched
//   - AbuseReports (*int): Number of abuse reports for this IP
//   - EnrichedAt (*time.Time): When threat intel was last enriched
//
// Example Usage:
//   log := &models.Log{
//       ThreatType: "xss",
//       Severity: "high",
//       Description: "XSS attempt detected",
//       ClientIP: "203.0.113.42",
//       Method: "GET",
//       URL: "/search?q=<script>alert(1)</script>",
//       Payload: "<script>alert(1)</script>",
//       Blocked: true,
//       BlockedBy: "auto",
//   }
//   db.Create(&log)
//
// Thread Safety: Not thread-safe. Use appropriate database transaction handling
// when creating/modifying logs concurrently.
//
// See Also: LogRepository, LogService
type Log struct {
	ID          uint      `gorm:"primarykey" json:"id"`
	CreatedAt   time.Time `gorm:"index" json:"created_at"`

	ThreatType  string `json:"threat_type"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	ClientIP    string `gorm:"index" json:"client_ip"`
	Method      string `json:"method"`
	URL         string `json:"url"`
	UserAgent   string `json:"user_agent"`
	Payload     string `json:"payload"`
	Blocked     bool   `json:"blocked"`
	// BlockedBy indicates how the threat was blocked: "auto" (by rule), "manual" (by operator), or "" (not blocked)
	BlockedBy   string `gorm:"default:''" json:"blocked_by"`

	// IP Source Metadata (from WAF)
	ClientIPSource    string `gorm:"default:''" json:"client_ip_source"`       // How the IP was extracted: x-public-ip, x-forwarded-for, x-real-ip, remote-addr
	ClientIPTrusted   bool   `json:"client_ip_trusted"`                        // Whether the IP source is from a trusted source (proxy, Tailscale, etc)
	ClientIPVPNReport bool   `json:"client_ip_vpn_report"`                     // Whether this is a self-reported IP from Tailscale/VPN client
	ClientIPPublic    string `gorm:"default:''" json:"client_ip_public"`       // The public IP reported by Tailscale/VPN client (from X-Public-IP header)
	IPTrustScore      *int   `json:"ip_trust_score,omitempty"`                 // IP Trust Score (0-100): 0-25=untrusted, 25-50=low, 50-75=neutral, 75-100=trusted

	// Threat Intelligence fields
	IPReputation     *int    `json:"ip_reputation,omitempty"`         // IP reputation score (0-100, higher = more suspicious)
	IsMalicious      bool    `json:"is_malicious"`                    // Whether IP is known to be malicious
	ASN              string  `json:"asn,omitempty"`                   // Autonomous System Number
	ISP              string  `json:"isp,omitempty"`                   // Internet Service Provider
	Country          string  `json:"country,omitempty"`               // Country code (ISO 3166-1 alpha-2)
	ThreatLevel      string  `json:"threat_level,omitempty"`          // Threat level: "critical", "high", "medium", "low", "none"
	ThreatSource     string  `json:"threat_source,omitempty"`         // Source of threat intel (e.g., "abuseipdb", "alienvault", "local_rules")
	IsOnBlocklist    bool    `json:"is_on_blocklist"`                 // Whether IP is on known blocklists
	BlocklistName    string  `json:"blocklist_name,omitempty"`        // Name of blocklist if matched
	AbuseReports     *int    `json:"abuse_reports,omitempty"`         // Number of abuse reports for this IP
	EnrichedAt       *time.Time `json:"enriched_at,omitempty"`        // When threat intel was last enriched
}