package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/service"
)

// logToWAFFile writes a manual block/unblock event to the WAF log file
// It retrieves the original threat data from database and writes complete log entry
func logToWAFFile(ctx context.Context, logService *service.LogService, ip string, description string, blocked bool, blockedBy string) error {
	// Find the original threat log to get all details
	logs, err := logService.GetLogsByIP(ctx, ip)
	if err != nil || len(logs) == 0 {
		return fmt.Errorf("could not find threat log for IP %s", ip)
	}

	// Find the matching log entry by description or threat_type
	var targetLog *models.Log
	for i := range logs {
		if logs[i].Description == description || logs[i].ThreatType == description {
			targetLog = &logs[i]
			break
		}
	}

	if targetLog == nil {
		return fmt.Errorf("could not find matching threat log")
	}

	// Create complete WAF log entry with all original data
	logEntry := map[string]interface{}{
		"timestamp":             targetLog.CreatedAt.Format(time.RFC3339Nano),
		"threat_type":           targetLog.ThreatType,
		"severity":              targetLog.Severity,
		"description":           targetLog.Description,
		"client_ip":             targetLog.ClientIP,
		"client_ip_source":      targetLog.ClientIPSource,
		"client_ip_trusted":     targetLog.ClientIPTrusted,
		"client_ip_vpn_report":  targetLog.ClientIPVPNReport,
		"method":                targetLog.Method,
		"url":                   targetLog.URL,
		"user_agent":            targetLog.UserAgent,
		"payload":               targetLog.Payload,
		"blocked":               blocked,
		"blocked_by":            blockedBy,
	}

	// Find the WAF log file - look in logs directory
	logDir := "logs"
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return err
	}

	// Get today's date for the log filename
	dateStr := time.Now().Format("2006-01-02")
	logFile := filepath.Join(logDir, fmt.Sprintf("waf_%s.log", dateStr))

	// Marshal to JSON
	data, err := json.Marshal(logEntry)
	if err != nil {
		return err
	}

	// Append to WAF log file
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	// Write to file
	_, err = f.Write(append(data, '\n'))
	return err
}

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

// NewUpdateThreatBlockStatusHandler updates the block status of a threat log
// Used for manual blocking (sets blocked=true, blocked_by="manual") and unblocking
func NewUpdateThreatBlockStatusHandler(logService *service.LogService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			IP          string `json:"ip" binding:"required"`
			Description string `json:"description" binding:"required"`
			Blocked     bool   `json:"blocked"` // true to block, false to unblock
			BlockedBy   string `json:"blocked_by"` // "manual" or ""
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": "Invalid request"})
			return
		}

		ctx := context.Background()

		// Update the threat log with the new block status
		updates := map[string]interface{}{
			"blocked":    req.Blocked,
			"blocked_by": req.BlockedBy,
		}

		// Update all threats matching this IP+description, regardless of current blocked status
		// This ensures we can update any threat to mark it as manually blocked
		if err := logService.UpdateLogsByIPAndDescription(ctx, req.IP, req.Description, updates); err != nil {
			c.JSON(500, gin.H{"error": "Failed to update threat block status"})
			return
		}

		// Log the manual block/unblock action to WAF log file with complete threat details
		if err := logToWAFFile(ctx, logService, req.IP, req.Description, req.Blocked, req.BlockedBy); err != nil {
			log.Printf("Warning: Failed to write to WAF log file: %v\n", err)
			// Don't fail the request if logging fails
		}

		c.JSON(200, gin.H{"message": "Threat block status updated successfully"})
	}
}