package models

import (
	"time"
	"gorm.io/gorm"
)

// FalsePositive represents a security event that was incorrectly flagged as a threat.
//
// Fields:
//   - ID (uint): Primary key identifier for the false positive entry
//   - CreatedAt (time.Time): Timestamp when the false positive was reported
//   - UpdatedAt (time.Time): Timestamp of last update
//   - DeletedAt (gorm.DeletedAt): Soft delete timestamp (indexed)
//   - ThreatType (string): Type of threat that was incorrectly detected
//   - Description (string): Description/reason from the rule that triggered
//   - ClientIP (string): IP address that triggered the false positive (indexed)
//   - Method (string): HTTP method of the request
//   - URL (string): URL that triggered the false positive
//   - Payload (string): The detected payload/content that was flagged
//   - UserAgent (string): User agent of the request
//   - Status (string): Review status - "pending", "reviewed", or "whitelisted" (default: "pending")
//   - ReviewNotes (string): Notes added during review
//   - ReviewedBy (uint): ID of the user who reviewed this
//   - ReviewedAt (*time.Time): Timestamp when reviewed
//
// Example Usage:
//   falsePositive := &models.FalsePositive{
//       ThreatType: "xss",
//       Description: "XSS pattern detected",
//       ClientIP: "203.0.113.42",
//       URL: "/api/search?q=<script>",
//       Status: "pending",
//   }
//   db.Create(&falsePositive)
//
// Thread Safety: Not thread-safe. Use appropriate database transaction handling
// when creating/modifying false positives concurrently.
//
// See Also: FalsePositiveRepository, FalsePositiveService
type FalsePositive struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	ThreatType  string `json:"threat_type"`
	Description string `json:"description"` // Description/reason from the rule
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
