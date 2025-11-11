package models

import "time"

// Log represents a WAF security event
type Log struct {
	ID          uint      `gorm:"primarykey" json:"id"`
	CreatedAt   time.Time `json:"created_at"`

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