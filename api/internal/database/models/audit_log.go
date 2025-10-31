package models

import "time"

// AuditLog tracks all user actions in the system
type AuditLog struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	CreatedAt time.Time `json:"created_at"`

	// User who performed the action
	UserID    uint   `gorm:"index" json:"user_id"`
	UserEmail string `json:"user_email"`

	// Action details
	Action      string `json:"action"` // e.g., "CREATE_RULE", "BLOCK_IP", "DELETE_USER", "LOGIN", "2FA_SETUP"
	Category    string `json:"category"` // e.g., "RULE", "BLOCKLIST", "USER_MANAGEMENT", "AUTH"
	Description string `json:"description"` // Human-readable description of what was done

	// Resource being acted upon
	ResourceType string `json:"resource_type"` // e.g., "rule", "ip", "user", "false_positive"
	ResourceID   string `json:"resource_id"`   // ID of the resource being modified

	// Additional context/details
	Details string `json:"details"` // JSON-encoded details of the action (what changed, parameters, etc.)

	// Result of the action
	Status string `json:"status"` // "success", "failure", "partial"
	Error  string `json:"error"`  // Error message if status is "failure"

	// IP address from which the action was performed
	IPAddress string `json:"ip_address"`
}
