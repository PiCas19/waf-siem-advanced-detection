package models

import (
	"time"
	"gorm.io/gorm"
)

// Rule represents a WAF detection rule for identifying and responding to security threats.
//
// Fields:
//   - ID (uint): Primary key identifier for the rule
//   - CreatedAt (time.Time): Timestamp when the rule was created
//   - UpdatedAt (time.Time): Timestamp of last update
//   - DeletedAt (gorm.DeletedAt): Soft delete timestamp (indexed)
//   - Name (string): Human-readable name of the rule (required)
//   - Pattern (string): Regular expression pattern to match threats (required)
//   - Type (string): Threat type - "xss", "sqli", "lfi", "rfi", "cmd" (required)
//   - Severity (string): Severity level - "low", "medium", "high", "critical" (default: "medium")
//   - Action (string): Action to take - "log" or "block" (default: "log")
//   - Enabled (bool): Whether this rule is currently active (default: true)
//   - Description (string): Detailed description of what this rule detects
//   - CreatedBy (uint): ID of the user who created this rule
//   - BlockEnabled (bool): Whether to reject the request immediately (default: false)
//   - DropEnabled (bool): Whether to terminate connection without response (default: false)
//   - RedirectEnabled (bool): Whether to redirect to security page (default: false)
//   - ChallengeEnabled (bool): Whether to require CAPTCHA verification (default: false)
//   - RedirectURL (string): URL to redirect to when RedirectEnabled is true
//   - IsManualBlock (bool): Whether this rule was created by manual threat blocking (default: false)
//
// Example Usage:
//   rule := &models.Rule{
//       Name: "XSS Detection",
//       Pattern: `<script[^>]*>.*?</script>`,
//       Type: "xss",
//       Severity: "high",
//       Action: "block",
//       Enabled: true,
//       BlockEnabled: true,
//   }
//   db.Create(&rule)
//
// Thread Safety: Not thread-safe. Use appropriate database transaction handling
// when creating/modifying rules concurrently.
//
// See Also: RuleRepository, RuleService
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