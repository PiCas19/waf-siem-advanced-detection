package models

import (
	"time"
	"gorm.io/gorm"
)

// WhitelistedIP represents a whitelisted IP address that should bypass security checks
type WhitelistedIP struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	IPAddress string `gorm:"uniqueIndex;not null" json:"ip_address"`
	Reason    string `json:"reason"`
	AddedBy   uint   `json:"added_by"`
}
