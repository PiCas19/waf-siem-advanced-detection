package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/logger"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/service"
)

// GetBlocklist - Returns the list of blocked IPs from database
func GetBlocklist(blocklistService *service.BlocklistService) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := context.Background()

		blockedIPs, err := blocklistService.GetActiveBlockedIPs(ctx)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to fetch blocked IPs"})
			return
		}

		c.JSON(200, gin.H{
			"blocked_ips": blockedIPs,
			"count":       len(blockedIPs),
		})
	}
}

// NewBlockIPHandler - Factory function to create a handler for blocking IPs
func NewBlockIPHandler(blocklistService *service.BlocklistService, logService *service.LogService) gin.HandlerFunc {
	return func(c *gin.Context) {
		BlockIPWithService(blocklistService, logService, c)
	}
}

// NewUnblockIPHandler - Factory function to create a handler for unblocking IPs
func NewUnblockIPHandler(blocklistService *service.BlocklistService, logService *service.LogService) gin.HandlerFunc {
	return func(c *gin.Context) {
		UnblockIPWithService(blocklistService, logService, c)
	}
}

// NewLogManualBlockHandler - Factory function to create a handler for logging manual blocks to WAF logs
func NewLogManualBlockHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			IP          string `json:"ip" binding:"required"`
			ThreatType  string `json:"threat_type" binding:"required"`
			Severity    string `json:"severity"`
			Description string `json:"description"`
			Payload     string `json:"payload"`
			URL         string `json:"url"`
			UserAgent   string `json:"user_agent"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": "Invalid request"})
			return
		}

		// Log the manual block to WAF logs
		LogManualBlockToWAFLog(req.IP, req.ThreatType, req.Severity, req.Description, req.Payload, req.URL, req.UserAgent)

		c.JSON(200, gin.H{"message": "Manual block logged successfully"})
	}
}

// BlockIPWithService - Blocks an IP for a specific rule/description
func BlockIPWithService(blocklistService *service.BlocklistService, logService *service.LogService, c *gin.Context) {
	var req struct {
		IP            string `json:"ip" binding:"required"`
		Threat        string `json:"threat" binding:"required"` // Rule name/description (e.g., "Detect API Enumeration", "XSS")
		Reason        string `json:"reason" binding:"required"`
		Permanent     bool   `json:"permanent"`
		DurationHours int    `json:"duration_hours"` // Custom duration in hours (-1 for permanent)
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	// Validate IP address
	validatedIP, err := ValidateIP(req.IP)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Validate threat type
	if err := ValidateThreat(req.Threat); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Validate reason
	if err := ValidateReason(req.Reason); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Validate duration
	if err := ValidateDuration(req.DurationHours); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	ctx := context.Background()

	blockedIP := models.BlockedIP{
		IPAddress:   validatedIP,
		Description: req.Threat,
		Reason:      req.Reason,
		Permanent:   req.Permanent || req.DurationHours == -1,
	}

	// Calculate expiration based on duration
	if !blockedIP.Permanent && req.DurationHours > 0 {
		expiresAt := time.Now().Add(time.Duration(int64(req.DurationHours)) * time.Hour)
		blockedIP.ExpiresAt = &expiresAt
	} else if !blockedIP.Permanent {
		// Fallback: default 24 hours
		expiresAt := time.Now().Add(24 * time.Hour)
		blockedIP.ExpiresAt = &expiresAt
	}

	// Check if block already exists
	existingBlock, err := blocklistService.GetBlockedIPByIPAndDescription(ctx, validatedIP, req.Threat)

	durationStr := "temporary"
	if blockedIP.Permanent {
		durationStr = "permanent"
	} else if req.DurationHours > 0 {
		durationStr = fmt.Sprintf("%d hours", req.DurationHours)
	}

	// Get the most recent log for this IP and threat to extract payload, url, user-agent
	logs, err := logService.GetLogsByIP(ctx, validatedIP)
	var payload, url, userAgent, severity, description string
	if err == nil && len(logs) > 0 {
		// Find the most recent log matching the threat type
		for _, log := range logs {
			if log.ThreatType == req.Threat || log.Description == req.Threat {
				payload = log.Payload
				url = log.URL
				userAgent = log.UserAgent
				severity = log.Severity
				description = log.Description
				break
			}
		}
	}

	// If we didn't find specific threat info, use defaults
	if description == "" {
		description = req.Threat
		severity = GetSeverityFromThreatType(req.Threat)
	}

	if err == nil && existingBlock != nil {
		// Update existing block
		blockedIP.ID = existingBlock.ID
		if err := blocklistService.UpdateBlockedIP(ctx, &blockedIP); err != nil {
			c.JSON(500, gin.H{"error": "Failed to update blocked IP"})
			return
		}

		c.JSON(200, gin.H{
			"message": "IP block updated successfully",
			"entry":   blockedIP,
		})
	} else {
		// Create new block
		if err := blocklistService.BlockIP(ctx, &blockedIP); err != nil {
			c.JSON(500, gin.H{"error": "Failed to create blocked IP"})
			return
		}

		// Emit blocking event to SIEM
		userEmail, _ := c.Get("user_email")
		userEmailStr := "unknown"
		if ue, ok := userEmail.(string); ok {
			userEmailStr = ue
		}

		emitBlockedIPEvent(req.IP, req.Threat, severity, description, req.Reason, durationStr, userEmailStr, c.ClientIP(), "success")

		// Log the manual block to WAF logs with complete threat info
		LogManualBlockToWAFLog(validatedIP, req.Threat, severity, description, payload, url, userAgent)

		c.JSON(201, gin.H{
			"message": "IP blocked successfully",
			"entry":   blockedIP,
		})
	}
}

// UnblockIPWithService - Unblocks an IP for a specific rule/description
func UnblockIPWithService(blocklistService *service.BlocklistService, logService *service.LogService, c *gin.Context) {
	ip := c.Param("ip")
	threat := c.Query("threat") // Get rule name from query string

	if threat == "" {
		c.JSON(400, gin.H{"error": "threat parameter required"})
		return
	}

	ctx := context.Background()

	// Find and delete the block
	blockedIP, err := blocklistService.GetBlockedIPByIPAndDescription(ctx, ip, threat)
	if err != nil || blockedIP == nil {
		c.JSON(404, gin.H{"error": "Blocked IP entry not found"})
		return
	}

	if err := blocklistService.UnblockIP(ctx, ip); err != nil {
		c.JSON(500, gin.H{"error": "Failed to delete blocked IP"})
		return
	}

	// Get the most recent log for this IP and threat to extract payload, url, user-agent
	logs, err := logService.GetLogsByIP(ctx, ip)
	var payload, url, userAgent, severity, description string
	if err == nil && len(logs) > 0 {
		// Find the most recent log matching the threat type
		for _, log := range logs {
			if log.ThreatType == threat || log.Description == threat {
				payload = log.Payload
				url = log.URL
				userAgent = log.UserAgent
				severity = log.Severity
				description = log.Description
				break
			}
		}
	}

	// If we didn't find specific threat info, use defaults
	if description == "" {
		description = threat
		severity = GetSeverityFromThreatType(threat)
	}

	// Log the manual unblock to WAF logs
	LogManualUnblockToWAFLog(ip, threat, severity, description, payload, url, userAgent)

	c.JSON(200, gin.H{"message": "IP unblocked successfully", "ip": ip, "threat": threat})
}

// UnblockIP - Deprecated: use NewUnblockIPHandler instead
func UnblockIP(c *gin.Context) {
	c.JSON(400, gin.H{"error": "use NewUnblockIPHandler"})
}

// refreshStatsOnClients notifica i client di ricaricare gli stats
// Il frontend farà un fetch a /api/stats per ottenere i dati aggiornati
func refreshStatsOnClients() {
	// Nota: Il WebSocket viene usato per notificare i client, ma il valore
	// di stats aggiornato verrà fetched dal frontend da /api/stats endpoint
	// che legge direttamente dal database
}

// IsIPBlocked - Checks if an IP is blocked for a specific rule/description in the database
// Note: This function is deprecated and should use BlocklistService instead
func IsIPBlocked(blocklistService *service.BlocklistService, ip string, description string) bool {
	ctx := context.Background()
	_, err := blocklistService.GetBlockedIPByIPAndDescription(ctx, ip, description)
	return err == nil
}

// NewGetBlocklistForWAF - Endpoint for WAF to fetch the list of blocked IPs
// Public endpoint (no auth required) - WAF needs to fetch this frequently
func NewGetBlocklistForWAF(blocklistService *service.BlocklistService) func(*gin.Context) {
	return func(c *gin.Context) {
		ctx := context.Background()

		blockedIPs, err := blocklistService.GetActiveBlockedIPs(ctx)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to fetch blocked IPs"})
			return
		}

		c.JSON(200, gin.H{
			"blocked_ips": blockedIPs,
			"count":       len(blockedIPs),
		})
	}
}

// NewGetWhitelistForWAF - Endpoint for WAF to fetch the list of whitelisted IPs
// Public endpoint (no auth required) - WAF needs to fetch this frequently
func NewGetWhitelistForWAF(whitelistService *service.WhitelistService) func(*gin.Context) {
	return func(c *gin.Context) {
		ctx := context.Background()

		whitelisted, err := whitelistService.GetAllWhitelistedIPs(ctx)
		if err != nil {
			c.JSON(500, gin.H{"error": "failed to fetch whitelist"})
			return
		}

		c.JSON(200, gin.H{
			"whitelisted_ips": whitelisted,
			"count":           len(whitelisted),
		})
	}
}

// emitBlockedIPEvent emits a blocking event to the SIEM via log file
func emitBlockedIPEvent(ip, threatType, severity, description, reason, duration, operator, operatorIP, status string) {
	// Create logs directory if it doesn't exist
	logsDir := "/var/log/caddy"
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		log.Printf("[ERROR] Failed to create logs directory: %v\n", err)
		return
	}

	// Initialize event logger for blocked IP events
	eventLogPath := logsDir + "/blocked_ip_events.log"
	eventLogger, err := logger.NewEventLogger(eventLogPath)
	if err != nil {
		log.Printf("[ERROR] Failed to initialize event logger: %v\n", err)
		return
	}
	defer eventLogger.Close()

	// Create the event with all available fields
	event := logger.BlockedIPEvent{
		Timestamp:   time.Now(),
		EventType:   "ip_blocked_manual",
		IP:          ip,
		ThreatType:  threatType,
		Severity:    severity,     // Now populated
		Description: description,   // Now populated
		Reason:      reason,        // Now populated
		Duration:    duration,
		Operator:    operator,
		OperatorIP:  operatorIP,
		Status:      status,
	}

	// Log the event
	if err := eventLogger.LogBlockedIPEvent(event); err != nil {
		log.Printf("[ERROR] Failed to log blocked IP event: %v\n", err)
		return
	}

	log.Printf("[INFO] Blocked IP event emitted: %s (threat: %s, duration: %s)\n", ip, threatType, duration)
}

// LogManualBlockToWAFLog writes a manual block entry to waf_wan.log and waf_lan.log
func LogManualBlockToWAFLog(ip, threatType, severity, description, payload, url, userAgent string) {
	logsDir := "/var/log/caddy"
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		log.Printf("[ERROR] Failed to create logs directory: %v\n", err)
		return
	}

	// Create log entry structure (simple JSON)
	entry := map[string]interface{}{
		"timestamp":    time.Now(),
		"threat_type":  threatType,
		"severity":     severity,
		"description":  description,
		"client_ip":    ip,
		"method":       "MANUAL_BLOCK",
		"url":          url,
		"user_agent":   userAgent,
		"payload":      payload,
		"blocked":      true,
		"blocked_by":   "manual",
	}

	// Marshal to JSON
	data, err := json.Marshal(entry)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal log entry: %v\n", err)
		return
	}

	// Write to both waf_wan.log and waf_lan.log
	for _, logFile := range []string{
		logsDir + "/waf_wan.log",
		logsDir + "/waf_lan.log",
	} {
		f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Printf("[ERROR] Failed to open log file %s: %v\n", logFile, err)
			continue
		}

		if _, err := f.Write(append(data, '\n')); err != nil {
			log.Printf("[ERROR] Failed to write to log file %s: %v\n", logFile, err)
		}
		f.Close()
	}

	log.Printf("[INFO] Manual block entry written to WAF logs: %s (threat: %s)\n", ip, threatType)
}

// LogManualUnblockToWAFLog writes a manual unblock entry to waf_wan.log and waf_lan.log
func LogManualUnblockToWAFLog(ip, threatType, severity, description, payload, url, userAgent string) {
	logsDir := "/var/log/caddy"
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		log.Printf("[ERROR] Failed to create logs directory: %v\n", err)
		return
	}

	// Create log entry structure (simple JSON)
	entry := map[string]interface{}{
		"timestamp":    time.Now(),
		"threat_type":  threatType,
		"severity":     severity,
		"description":  description,
		"client_ip":    ip,
		"method":       "MANUAL_UNBLOCK",
		"url":          url,
		"user_agent":   userAgent,
		"payload":      payload,
		"blocked":      false,
		"blocked_by":   "",
	}

	// Marshal to JSON
	data, err := json.Marshal(entry)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal log entry: %v\n", err)
		return
	}

	// Write to both waf_wan.log and waf_lan.log
	for _, logFile := range []string{
		logsDir + "/waf_wan.log",
		logsDir + "/waf_lan.log",
	} {
		f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Printf("[ERROR] Failed to open log file %s: %v\n", logFile, err)
			continue
		}

		if _, err := f.Write(append(data, '\n')); err != nil {
			log.Printf("[ERROR] Failed to write to log file %s: %v\n", logFile, err)
		}
		f.Close()
	}

	log.Printf("[INFO] Manual unblock entry written to WAF logs: %s (threat: %s)\n", ip, threatType)
}