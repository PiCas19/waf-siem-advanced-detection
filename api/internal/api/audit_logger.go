package api

import (
	"encoding/json"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"gorm.io/gorm"
)

// LogAuditAction logs a user action to the audit log
func LogAuditAction(db *gorm.DB, userID uint, userEmail string, action string, category string, resourceType string, resourceID string, description string, details map[string]interface{}, ipAddress string) error {
	// Convert details to JSON
	var detailsJSON string
	if details != nil {
		if jsonData, err := json.Marshal(details); err == nil {
			detailsJSON = string(jsonData)
		}
	}

	auditLog := models.AuditLog{
		UserID:       userID,
		UserEmail:    userEmail,
		Action:       action,
		Category:     category,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Description:  description,
		Details:      detailsJSON,
		Status:       "success",
		IPAddress:    ipAddress,
		CreatedAt:    time.Now(),
	}

	return db.Create(&auditLog).Error
}

// LogAuditActionWithError logs a failed action to the audit log
func LogAuditActionWithError(db *gorm.DB, userID uint, userEmail string, action string, category string, resourceType string, resourceID string, description string, details map[string]interface{}, ipAddress string, errMsg string) error {
	// Convert details to JSON
	var detailsJSON string
	if details != nil {
		if jsonData, err := json.Marshal(details); err == nil {
			detailsJSON = string(jsonData)
		}
	}

	auditLog := models.AuditLog{
		UserID:       userID,
		UserEmail:    userEmail,
		Action:       action,
		Category:     category,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Description:  description,
		Details:      detailsJSON,
		Status:       "failure",
		Error:        errMsg,
		IPAddress:    ipAddress,
		CreatedAt:    time.Now(),
	}

	return db.Create(&auditLog).Error
}

// LogAuthAction logs authentication-related actions
func LogAuthAction(db *gorm.DB, userID uint, userEmail string, action string, description string, success bool, ipAddress string) error {
	status := "success"
	if !success {
		status = "failure"
	}

	auditLog := models.AuditLog{
		UserID:       userID,
		UserEmail:    userEmail,
		Action:       action,
		Category:     "AUTH",
		ResourceType: "user",
		ResourceID:   userEmail,
		Description:  description,
		Status:       status,
		IPAddress:    ipAddress,
		CreatedAt:    time.Now(),
	}

	return db.Create(&auditLog).Error
}

// LogBlocklistAction logs IP blocking/unblocking actions
func LogBlocklistAction(db *gorm.DB, userID uint, userEmail string, action string, ipAddress string, threatType string, duration string, ipRequestAddr string) error {
	details := map[string]interface{}{
		"ip":          ipAddress,
		"threat_type": threatType,
		"duration":    duration,
	}

	return LogAuditAction(
		db,
		userID,
		userEmail,
		action,
		"BLOCKLIST",
		"ip",
		ipAddress,
		"IP "+action+": "+ipAddress+" for threat: "+threatType,
		details,
		ipRequestAddr,
	)
}

// LogWhitelistAction logs whitelist add/remove actions
func LogWhitelistAction(db *gorm.DB, userID uint, userEmail string, action string, ipAddress string, reason string, ipRequestAddr string) error {
	details := map[string]interface{}{
		"ip":     ipAddress,
		"reason": reason,
	}

	return LogAuditAction(
		db,
		userID,
		userEmail,
		action,
		"WHITELIST",
		"ip",
		ipAddress,
		"IP "+action+": "+ipAddress+" ("+reason+")",
		details,
		ipRequestAddr,
	)
}

// LogFalsePositiveAction logs false positive report/update actions
func LogFalsePositiveAction(db *gorm.DB, userID uint, userEmail string, action string, fpID string, threatType string, clientIP string, status string, ipRequestAddr string) error {
	details := map[string]interface{}{
		"threat_type": threatType,
		"client_ip":   clientIP,
		"status":      status,
	}

	return LogAuditAction(
		db,
		userID,
		userEmail,
		action,
		"FALSE_POSITIVE",
		"false_positive",
		fpID,
		"False Positive "+action+": "+threatType+" from "+clientIP,
		details,
		ipRequestAddr,
	)
}

// LogRuleAction logs rule create/update/delete actions
func LogRuleAction(db *gorm.DB, userID uint, userEmail string, action string, ruleID string, ruleName string, details map[string]interface{}, ipRequestAddr string) error {
	return LogAuditAction(
		db,
		userID,
		userEmail,
		action,
		"RULE",
		"rule",
		ruleID,
		"Rule "+action+": "+ruleName,
		details,
		ipRequestAddr,
	)
}
