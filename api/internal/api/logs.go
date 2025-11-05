package api

import (
	"github.com/gin-gonic/gin"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"gorm.io/gorm"
)

// isDefaultThreatType checks if a threat type is a default WAF rule
func isDefaultThreatType(threatType string) bool {
	defaultThreats := map[string]bool{
		"XSS":                        true,
		"SQL_INJECTION":              true,
		"LFI":                        true,
		"RFI":                        true,
		"COMMAND_INJECTION":          true,
		"XXE":                        true,
		"LDAP_INJECTION":             true,
		"SSTI":                       true,
		"HTTP_RESPONSE_SPLITTING":    true,
		"PROTOTYPE_POLLUTION":        true,
		"PATH_TRAVERSAL":             true,
		"SSRF":                       true,
		"NOSQL_INJECTION":            true,
	}
	return defaultThreats[threatType]
}

func NewGetLogsHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var logs []models.Log
		var auditLogs []models.AuditLog

		// Fetch security logs
		if err := db.Order("created_at DESC").Find(&logs).Error; err != nil {
			c.JSON(500, gin.H{"error": "failed to fetch logs"})
			return
		}

		// Fetch audit logs
		if err := db.Order("created_at DESC").Find(&auditLogs).Error; err != nil {
			// If audit logs fail, continue with just security logs
		}

		// Normalize blockedBy for default threats
		// Default threats should always show blockedBy="auto" even if manually blocked
		// Also ensure Severity is always set
		for i := range logs {
			if isDefaultThreatType(logs[i].ThreatType) {
				logs[i].BlockedBy = "auto"
			}

			// Ensure severity is always set (for backwards compatibility with old logs)
			if logs[i].Severity == "" || logs[i].Severity == "N/A" {
				logs[i].Severity = GetSeverityFromThreatType(logs[i].ThreatType)
			}
		}

		c.JSON(200, gin.H{
			"security_logs": logs,
			"audit_logs":    auditLogs,
			"logs":          logs, // Keep for backward compatibility
		})
	}
}