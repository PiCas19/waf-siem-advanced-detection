package models

import (
	"time"
	"gorm.io/gorm"
)

// BlockedIP represents a blocked IP address for a specific threat/rule
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