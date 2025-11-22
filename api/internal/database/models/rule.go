package models

import (
	"time"
	"gorm.io/gorm"
)

// Rule represents a WAF detection rule
type Rule struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Name        string `gorm:"not null" json:"name"`
	Pattern     string `gorm:"not null" json:"pattern"`
	Type        string `gorm:"not null" json:"type"` // xss, sqli, lfi, rfi, cmd
	Severity    string `gorm:"default:'medium'" json:"severity"` // low, medium, high, critical
	Action      string `gorm:"default:'log'" json:"action"` // log, block
	Enabled     bool   `gorm:"default:true" json:"enabled"`
	Description string `json:"description"`
	CreatedBy   uint   `json:"created_by"`

	// Automated blocking actions
	BlockEnabled      bool   `gorm:"default:false" json:"block_enabled"`      // Block - Reject request immediately
	DropEnabled       bool   `gorm:"default:false" json:"drop_enabled"`       // Drop - Terminate connection without response
	RedirectEnabled   bool   `gorm:"default:false" json:"redirect_enabled"`   // Redirect - Redirect to security page
	ChallengeEnabled  bool   `gorm:"default:false" json:"challenge_enabled"`  // Challenge - Require CAPTCHA verification
	RedirectURL       string `json:"redirect_url"`                             // URL to redirect to

	// Manual block flag - created by manual block action, cannot be edited
	IsManualBlock bool `gorm:"default:false" json:"is_manual_block"` // True if created by manual threat blocking
}