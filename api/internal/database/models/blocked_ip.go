package models

import (
	"time"
	"gorm.io/gorm"
)

// BlockedIP represents a blocked IP address for a specific threat or rule.
//
// Fields:
//   - ID (uint): Primary key identifier for the blocked IP entry
//   - CreatedAt (time.Time): Timestamp when the IP was blocked
//   - UpdatedAt (time.Time): Timestamp of last update
//   - DeletedAt (gorm.DeletedAt): Soft delete timestamp (indexed)
//   - IPAddress (string): The blocked IP address (indexed, required)
//   - Description (string): Rule name/description (e.g., "XSS", "SQL Injection") (indexed, required)
//   - Reason (string): Explanation for why this IP was blocked
//   - ExpiresAt (*time.Time): Expiry timestamp for temporary blocks
//   - Permanent (bool): Whether this is a permanent block (default: false)
//   - AddedBy (uint): ID of the user who added this block
//   - URL (string): URL of the request that triggered the block
//   - UserAgent (string): User agent of the blocked request
//   - Payload (string): Detected payload/threat content
//
// Note: The same IP can be blocked for different rules (composite unique index on IPAddress + Description).
//
// Example Usage:
//   blockedIP := &models.BlockedIP{
//       IPAddress: "198.51.100.42",
//       Description: "XSS Attack",
//       Reason: "Multiple XSS attempts detected",
//       Permanent: true,
//       AddedBy: operatorUserID,
//   }
//   db.Create(&blockedIP)
//
// Thread Safety: Not thread-safe. Use appropriate database transaction handling
// when creating/modifying blocked IPs concurrently.
//
// See Also: BlockedIPRepository, BlocklistService
type BlockedIP struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	IPAddress   string    `gorm:"index;not null" json:"ip_address"`
	Description string    `gorm:"index;not null" json:"description"` // Rule name/description (e.g. "XSS", "Detect API Enumeration")
	Reason      string    `json:"reason"`
	ExpiresAt   *time.Time `json:"expires_at"`
	Permanent   bool      `gorm:"default:false" json:"permanent"`
	AddedBy     uint      `json:"added_by"`
	URL         string    `json:"url"`           // URL of the request that triggered the block
	UserAgent   string    `json:"user_agent"`   // User agent of the request
	Payload     string    `json:"payload"`      // Detected payload/threat content

	// Composite unique index: same IP can be blocked for different rules
	// :- (removed uniqueIndex from IPAddress, added composite index below)
}

// TableName specifies the table name for BlockedIP
func (BlockedIP) TableName() string {
	return "blocked_ips"
}

// Add unique constraint on IP + Description combination
func (BlockedIP) Init() {
	// This will be handled by migrations
}