package api

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/service"
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

// NewGetLogsHandler returns security and audit logs with service layer
func NewGetLogsHandler(logService *service.LogService, auditLogService *service.AuditLogService, blocklistService *service.BlocklistService) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := context.Background()

		// Fetch security logs
		logs, err := logService.GetAllLogs(ctx)
		if err != nil {
			c.JSON(500, gin.H{"error": "failed to fetch logs"})
			return
		}

		// Fetch audit logs
		auditLogs, err := auditLogService.GetAllAuditLogs(ctx)
		if err != nil {
			// If audit logs fail, continue with just security logs
			auditLogs = []models.AuditLog{}
		}

		// Fetch all manually blocked IPs
		var blockedIPsList []models.BlockedIP
		blocklistResult, err := blocklistService.GetActiveBlockedIPs(ctx)
		if err == nil {
			blockedIPsList = blocklistResult // If successful, use the result
		}

		// Create a map of blocked IPs for quick lookup: "ip::threat" -> true
		// Store both by Description (from dashboard) and alternative keys for matching
		blockedMap := make(map[string]bool)
		for _, blocked := range blockedIPsList {
			// Primary key: IP + Description (as saved from dashboard)
			key := blocked.IPAddress + "::" + blocked.Description
			blockedMap[key] = true
		}

		// Normalize blockedBy for default threats and check manual blocks
		// Default threats should always show blockedBy="auto" even if manually blocked
		// Custom threats should show blockedBy="manual" if in the blocklist
		// Also ensure Severity is always set
		for i := range logs {
			if isDefaultThreatType(logs[i].ThreatType) {
				logs[i].BlockedBy = "auto"
			} else if logs[i].BlockedBy != "auto" {
				// For custom threats, only override BlockedBy if it's not already "auto"
				// This preserves auto-blocked threats from being marked as manual
				// For custom threats, check if they're in the blocklist
				key := logs[i].ClientIP + "::" + (logs[i].Description)
				if logs[i].Description == "" {
					key = logs[i].ClientIP + "::" + logs[i].ThreatType
				}

				if blockedMap[key] {
					logs[i].BlockedBy = "manual"
					logs[i].Blocked = true
				}
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