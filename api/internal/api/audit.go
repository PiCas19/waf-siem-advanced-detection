package api

import (
	"encoding/json"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/logger"
)

// LogAudit logs a user action to the audit log
func LogAudit(db *gorm.DB, c *gin.Context, action, category, description, resourceType, resourceID string, details map[string]interface{}, status, errorMsg string) error {
	// Get user ID from context (set by AuthMiddleware)
	userIDInterface, _ := c.Get("user_id")
	userID := uint(0)
	if uid, ok := userIDInterface.(uint); ok {
		userID = uid
	}

	// Get user email from context
	userEmailInterface, _ := c.Get("user_email")
	userEmail := ""
	if email, ok := userEmailInterface.(string); ok {
		userEmail = email
	}

	// Get client IP address
	ipAddress := c.ClientIP()

	// Encode details as JSON
	detailsJSON := ""
	if details != nil {
		if bytes, err := json.Marshal(details); err == nil {
			detailsJSON = string(bytes)
		}
	}

	// Create audit log entry
	auditLog := models.AuditLog{
		UserID:       userID,
		UserEmail:    userEmail,
		Action:       action,
		Category:     category,
		Description:  description,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Details:      detailsJSON,
		Status:       status,
		Error:        errorMsg,
		IPAddress:    ipAddress,
	}

	// Save to database
	if err := db.Create(&auditLog).Error; err != nil {
		logger.Log.WithError(err).Error("Failed to save audit log")
		return err
	}

	return nil
}

// LogAuditSimple is a simpler version for basic actions
func LogAuditSimple(db *gorm.DB, c *gin.Context, action, category, description, status string) error {
	return LogAudit(db, c, action, category, description, "", "", nil, status, "")
}

// LogAuditWithError logs an action that failed
func LogAuditWithError(db *gorm.DB, c *gin.Context, action, category, description, resourceType, resourceID string, details map[string]interface{}, errMsg string) error {
	return LogAudit(db, c, action, category, description, resourceType, resourceID, details, "failure", errMsg)
}

// LogAuditSuccess logs a successful action
func LogAuditSuccess(db *gorm.DB, c *gin.Context, action, category, description, resourceType, resourceID string, details map[string]interface{}) error {
	return LogAudit(db, c, action, category, description, resourceType, resourceID, details, "success", "")
}
