package models

import (
	"time"
	"gorm.io/gorm"
)

// BlockedIP represents a blocked IP address
type BlockedIP struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
	
	IPAddress  string    `gorm:"uniqueIndex;not null" json:"ip_address"`
	Reason     string    `json:"reason"`
	ExpiresAt  time.Time `json:"expires_at"`
	Permanent  bool      `gorm:"default:false" json:"permanent"`
	AddedBy    uint      `json:"added_by"`
}