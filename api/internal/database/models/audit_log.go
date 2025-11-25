package models

import "time"

// AuditLog tracks all user actions in the system for security auditing and compliance.
//
// Fields:
//   - ID (uint): Primary key identifier for the audit log entry
//   - CreatedAt (time.Time): Timestamp when the action was performed
//   - UserID (uint): ID of the user who performed the action (indexed)
//   - UserEmail (string): Email address of the user
//   - Action (string): Type of action performed (e.g., "CREATE_RULE", "BLOCK_IP", "LOGIN")
//   - Category (string): Category of the action (e.g., "RULE", "BLOCKLIST", "AUTH")
//   - Description (string): Human-readable description of what was done
//   - ResourceType (string): Type of resource acted upon (e.g., "rule", "ip", "user")
//   - ResourceID (string): ID of the resource being modified
//   - Details (string): JSON-encoded details of the action (what changed, parameters, etc.)
//   - Status (string): Result of the action - "success", "failure", or "partial"
//   - Error (string): Error message if status is "failure"
//   - IPAddress (string): IP address from which the action was performed
//
// Example Usage:
//   auditLog := &models.AuditLog{
//       UserID: user.ID,
//       UserEmail: user.Email,
//       Action: "CREATE_RULE",
//       Category: "RULE",
//       ResourceType: "rule",
//       ResourceID: fmt.Sprintf("%d", ruleID),
//       Description: "Created new XSS detection rule",
//       Status: "success",
//       IPAddress: "192.168.1.100",
//   }
//   db.Create(&auditLog)
//
// Thread Safety: This struct itself is not thread-safe. Use appropriate database
// transaction handling and locking when creating/modifying audit logs concurrently.
//
// See Also: AuditLogRepository, AuditLogService
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
