package api

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/helpers"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/logger"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/service"
)

// logToWAFFile writes a manual block/unblock event to the WAF log files
// Writes to either /var/log/caddy/waf_wan.log or /var/log/caddy/waf_lan.log
// depending on the ClientIPSource of the threat
func logToWAFFile(ctx context.Context, logService *service.LogService, ip string, description string, blocked bool, blockedBy string) error {
	logger.Log.WithFields(map[string]interface{}{
		"ip":          ip,
		"description": description,
		"blocked":     blocked,
		"blocked_by":  blockedBy,
	}).Debug("logToWAFFile called")

	// Find the original threat log to get all details
	logs, err := logService.GetLogsByIP(ctx, ip)
	logger.Log.WithFields(map[string]interface{}{
		"ip":        ip,
		"log_count": len(logs),
	}).WithError(err).Debug("GetLogsByIP result")

	var targetLog *models.Log

	if err == nil && len(logs) > 0 {
		// Find the matching log entry by description or threat_type
		for i := range logs {
			if logs[i].Description == description || logs[i].ThreatType == description {
				targetLog = &logs[i]
				logger.Log.Debug("Found matching log entry")
				break
			}
		}

		// If no exact match found, use the first log as a fallback
		if targetLog == nil && len(logs) > 0 {
			logger.Log.Debug("No exact match found, using first log as fallback")
			targetLog = &logs[0]
		}
	}

	if targetLog == nil {
		logger.Log.WithFields(map[string]interface{}{
			"ip":          ip,
			"description": description,
		}).Warn("Could not find threat log in database")
		// Create a minimal log entry with available data - don't fail the operation
	}

	// Determine if this is WAN or LAN traffic based on ClientIPSource
	// WAN traffic comes from Tailscale/VPN (x-public-ip, x-forwarded-for)
	// LAN traffic comes from internal sources (remote-addr, internal proxies)
	isWAN := false
	if targetLog != nil {
		// Check if it's from a Tailscale/VPN source
		isWAN = targetLog.ClientIPVPNReport ||
		        targetLog.ClientIPSource == "x-public-ip" ||
		        (targetLog.ClientIPSource == "x-forwarded-for" && targetLog.ClientIPTrusted)
	}

	// Determine which log file to write to
	var logFilePath string
	if isWAN {
		logFilePath = "/var/log/caddy/waf_wan.log"
	} else {
		logFilePath = "/var/log/caddy/waf_lan.log"
	}
	logger.Log.WithFields(map[string]interface{}{
		"traffic_type": map[bool]string{true: "WAN", false: "LAN"}[isWAN],
		"log_path":     logFilePath,
	}).Debug("Determined traffic type and log path")

	// Create the WAF log entry struct matching the WAF logger format
	wafLogEntry := models.Log{
		CreatedAt:        time.Now(),
		ThreatType:       description,
		Severity:         "Unknown",
		Description:      description,
		ClientIP:         ip,
		ClientIPSource:   "manual-dashboard",
		ClientIPTrusted:  false,
		ClientIPVPNReport: false,
		Method:           "",
		URL:              "",
		UserAgent:        "",
		Payload:          "",
		Blocked:          blocked,
		BlockedBy:        blockedBy,
	}

	// If we found the original log, use its data instead
	if targetLog != nil {
		wafLogEntry = *targetLog
		wafLogEntry.Blocked = blocked
		wafLogEntry.BlockedBy = blockedBy
		wafLogEntry.CreatedAt = time.Now() // Update timestamp to block action time
	}

	// Create directory if it doesn't exist
	logDir := "/var/log/caddy"
	if err := os.MkdirAll(logDir, 0755); err != nil {
		logger.Log.WithFields(map[string]interface{}{
			"log_dir": logDir,
		}).WithError(err).Warn("Could not create log directory")
		// Try fallback location in case /var/log/caddy is not writable
		logDir = "/tmp/caddy_logs"
		if err := os.MkdirAll(logDir, 0755); err != nil {
			logger.Log.WithError(err).Error("Could not create fallback log directory")
			return fmt.Errorf("could not create log directory")
		}
		if isWAN {
			logFilePath = filepath.Join(logDir, "waf_wan.log")
		} else {
			logFilePath = filepath.Join(logDir, "waf_lan.log")
		}
	}

	logger.Log.WithField("log_path", logFilePath).Debug("Writing to log file")

	// Marshal to JSON
	logEntryMap := map[string]interface{}{
		"timestamp":             wafLogEntry.CreatedAt.Format(time.RFC3339Nano),
		"threat_type":           wafLogEntry.ThreatType,
		"severity":              wafLogEntry.Severity,
		"description":           wafLogEntry.Description,
		"client_ip":             wafLogEntry.ClientIP,
		"client_ip_source":      wafLogEntry.ClientIPSource,
		"client_ip_trusted":     wafLogEntry.ClientIPTrusted,
		"client_ip_vpn_report":  wafLogEntry.ClientIPVPNReport,
		"method":                wafLogEntry.Method,
		"url":                   wafLogEntry.URL,
		"user_agent":            wafLogEntry.UserAgent,
		"payload":               wafLogEntry.Payload,
		"blocked":               wafLogEntry.Blocked,
		"blocked_by":            wafLogEntry.BlockedBy,
	}

	data, err := json.Marshal(logEntryMap)
	if err != nil {
		logger.Log.WithError(err).Error("Failed to marshal JSON")
		return err
	}

	// Append to WAF log file
	f, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logger.Log.WithFields(map[string]interface{}{
			"log_path": logFilePath,
		}).WithError(err).Error("Failed to open log file")
		return err
	}
	defer f.Close()

	// Write to file
	_, err = f.Write(append(data, '\n'))
	if err != nil {
		logger.Log.WithError(err).Error("Failed to write to log file")
	} else {
		logger.Log.WithField("log_path", logFilePath).Debug("Log entry written successfully")
	}
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

// NewGetLogsHandler godoc
// @Summary Get security and audit logs
// @Description Returns paginated list of security logs with audit logs
// @Tags Logs
// @Accept json
// @Produce json
// @Param limit query int false "Number of items per page (default 20, max 100)" default(20)
// @Param offset query int false "Pagination offset (default 0)" default(0)
// @Param sort query string false "Sort field (id, client_ip, threat_type, severity, created_at, blocked)"
// @Param order query string false "Sort order (asc or desc)" default(asc)
// @Success 200 {object} map[string]interface{} "Security and audit logs with pagination"
// @Failure 400 {object} map[string]interface{} "Invalid pagination parameters"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /logs [get]
// @Security BearerAuth
func NewGetLogsHandler(logService *service.LogService, auditLogService *service.AuditLogService, blocklistService *service.BlocklistService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Parse pagination parameters
		limit, offset, _, _, err := helpers.ParsePaginationParams(c)
		if err != nil {
			BadRequestWithCode(c, ErrInvalidRequest, err.Error())
			return
		}

		ctx := c.Request.Context()

		// Fetch paginated security logs
		logs, total, err := logService.GetLogsPaginated(ctx, offset, limit)
		if err != nil {
			InternalServerErrorWithCode(c, ErrServiceError, "Failed to fetch logs")
			return
		}

		// Fetch audit logs (no pagination, for now get recent ones)
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

		// Build paginated response for security logs
		paginatedResponse := helpers.BuildStandardPaginatedResponse(logs, limit, offset, total)

		c.JSON(200, gin.H{
			"security_logs": paginatedResponse.Items,
			"pagination":    paginatedResponse.Pagination,
			"audit_logs":    auditLogs,
			"logs":          paginatedResponse.Items, // Keep for backward compatibility
		})
	}
}

// NewUpdateThreatBlockStatusHandler godoc
// @Summary Update threat block status
// @Description Updates the blocked status and blocked_by field for a threat
// @Tags Logs
// @Accept json
// @Produce json
// @Param request body object{ip=string,description=string,blocked=boolean,blocked_by=string} true "Block status update"
// @Success 200 {object} map[string]interface{} "Threat block status updated"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /logs/threat-block-status [put]
// @Security BearerAuth
func NewUpdateThreatBlockStatusHandler(logService *service.LogService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			IP          string `json:"ip" binding:"required"`
			Description string `json:"description" binding:"required"`
			Blocked     bool   `json:"blocked"` // true to block, false to unblock
			BlockedBy   string `json:"blocked_by"` // "manual" or ""
		}

		if !ValidateJSON(c, &req) {
			return
		}

		ctx := c.Request.Context()

		// Update the threat log with the new block status
		updates := map[string]interface{}{
			"blocked":    req.Blocked,
			"blocked_by": req.BlockedBy,
		}

		// Update all threats matching this IP+description, regardless of current blocked status
		// This ensures we can update any threat to mark it as manually blocked
		if err := logService.UpdateLogsByIPAndDescription(ctx, req.IP, req.Description, updates); err != nil {
			InternalServerErrorWithCode(c, ErrDatabaseError, "Failed to update threat block status")
			return
		}

		// Log the manual block/unblock action to WAF log file with complete threat details
		if err := logToWAFFile(ctx, logService, req.IP, req.Description, req.Blocked, req.BlockedBy); err != nil {
			logger.Log.WithError(err).Warn("Failed to write to WAF log file")
			// Don't fail the request if logging fails
		}

		c.JSON(200, gin.H{"message": "Threat block status updated successfully"})
	}
}