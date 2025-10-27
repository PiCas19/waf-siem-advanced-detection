package models

import (
	"time"
	"gorm.io/gorm"
)

// FalsePositive represents a security event flagged as a false positive
type FalsePositive struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	ThreatType  string `json:"threat_type"`
	ClientIP    string `gorm:"index" json:"client_ip"`
	Method      string `json:"method"`
	URL         string `json:"url"`
	Payload     string `json:"payload"`
	UserAgent   string `json:"user_agent"`

	// Status: pending, reviewed, whitelisted
	Status string `gorm:"default:'pending'" json:"status"`

	// Notes for review
	ReviewNotes string `json:"review_notes"`
	ReviewedBy  uint   `json:"reviewed_by"`
	ReviewedAt  *time.Time `json:"reviewed_at"`
}
