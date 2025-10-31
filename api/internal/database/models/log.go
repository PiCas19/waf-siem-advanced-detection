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
}