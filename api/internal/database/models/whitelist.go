package models

import (
	"time"
	"gorm.io/gorm"
)

// WhitelistedIP represents a whitelisted IP address that should bypass security checks.
//
// Fields:
//   - ID (uint): Primary key identifier for the whitelisted IP entry
//   - CreatedAt (time.Time): Timestamp when the IP was whitelisted
//   - UpdatedAt (time.Time): Timestamp of last update
//   - DeletedAt (gorm.DeletedAt): Soft delete timestamp (indexed)
//   - IPAddress (string): The whitelisted IP address (unique, indexed, required)
//   - Reason (string): Explanation for why this IP is whitelisted
//   - AddedBy (uint): ID of the user who added this IP to the whitelist
//
// Example Usage:
//   whitelistedIP := &models.WhitelistedIP{
//       IPAddress: "203.0.113.42",
//       Reason: "Corporate office IP",
//       AddedBy: adminUserID,
//   }
//   db.Create(&whitelistedIP)
//
// Thread Safety: This struct itself is not thread-safe. Use appropriate database
// transaction handling when creating/modifying whitelisted IPs concurrently.
//
// See Also: WhitelistedIPRepository, WhitelistService
type WhitelistedIP struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	IPAddress string `gorm:"uniqueIndex;not null" json:"ip_address"`
	Reason    string `json:"reason"`
	AddedBy   uint   `json:"added_by"`
}
