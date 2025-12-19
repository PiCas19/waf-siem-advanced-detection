package api

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/dto"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/helpers"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/logger"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/service"
)

// GetBlocklist godoc
// @Summary Get blocked IPs list
// @Description Returns paginated list of blocked IPs with optional filtering and sorting
// @Tags Blocklist
// @Accept json
// @Produce json
// @Param limit query int false "Number of items per page (default 20, max 100)" default(20)
// @Param offset query int false "Pagination offset (default 0)" default(0)
// @Param sort query string false "Sort field (id, ip_address, created_at, expires_at)"
// @Param order query string false "Sort order (asc or desc)" default(asc)
// @Success 200 {object} dto.StandardPaginatedResponse{items=[]models.BlockedIP}
// @Failure 400 {object} map[string]interface{} "Invalid pagination parameters"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /blocklist [get]
// @Security BearerAuth
func GetBlocklist(blocklistService *service.BlocklistService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Parse pagination parameters
		limit, offset, _, _, err := helpers.ParsePaginationParams(c)
		if err != nil {
			BadRequestWithCode(c, ErrInvalidRequest, err.Error())
			return
		}

		ctx := c.Request.Context()

		// Fetch paginated blocked IPs
		blockedIPs, total, err := blocklistService.GetBlockedIPsPaginated(ctx, offset, limit)
		if err != nil {
			InternalServerErrorWithCode(c, ErrServiceError, "Failed to fetch blocked IPs")
			return
		}

		// Build paginated response
		response := helpers.BuildStandardPaginatedResponse(blockedIPs, limit, offset, total)
		c.JSON(200, response)
	}
}

// NewBlockIPHandler godoc
// @Summary Block an IP address
// @Description Blocks an IP address for a specific rule/threat
// @Tags Blocklist
// @Accept json
// @Produce json
// @Param request body object{ip=string,threat=string,reason=string,permanent=boolean,duration_hours=integer} true "Block request"
// @Success 201 {object} map[string]interface{} "IP blocked successfully"
// @Success 200 {object} map[string]interface{} "IP block updated"
// @Failure 400 {object} map[string]interface{} "Invalid IP, threat, or parameters"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /blocklist [post]
// @Security BearerAuth
func NewBlockIPHandler(blocklistService *service.BlocklistService, logService *service.LogService, ruleService *service.RuleService) gin.HandlerFunc {
	return func(c *gin.Context) {
		BlockIPWithService(blocklistService, logService, ruleService, c)
	}
}

// NewUnblockIPHandler godoc
// @Summary Unblock an IP address
// @Description Removes an IP address from the blocklist
// @Tags Blocklist
// @Accept json
// @Produce json
// @Param ip path string true "IP address"
// @Param threat query string true "Threat/rule name"
// @Success 200 {object} map[string]interface{} "IP unblocked successfully"
// @Failure 400 {object} map[string]interface{} "Missing threat parameter"
// @Failure 404 {object} map[string]interface{} "Blocked IP not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /blocklist/{ip} [delete]
// @Security BearerAuth
func NewUnblockIPHandler(blocklistService *service.BlocklistService, logService *service.LogService, ruleService *service.RuleService) gin.HandlerFunc {
	return func(c *gin.Context) {
		UnblockIPWithService(blocklistService, logService, ruleService, c)
	}
}

// BlockIPWithService - Blocks an IP for a specific rule/description
func BlockIPWithService(blocklistService *service.BlocklistService, logService *service.LogService, ruleService *service.RuleService, c *gin.Context) {
	var req struct {
		IP            string `json:"ip" binding:"required"`
		Threat        string `json:"threat" binding:"required"` // Rule name/description (e.g., "Detect API Enumeration", "XSS")
		Reason        string `json:"reason" binding:"required"`
		Permanent     bool   `json:"permanent"`
		DurationHours int    `json:"duration_hours"` // Custom duration in hours (-1 for permanent)
		URL           string `json:"url"`            // URL of the request
		UserAgent     string `json:"user_agent"`    // User agent of the request
		Payload       string `json:"payload"`       // Threat payload
	}

	if !ValidateJSON(c, &req) {
		return
	}

	// Validate IP address
	validatedIP, err := ValidateIP(req.IP)
	if err != nil {
		BadRequestWithCode(c, ErrInvalidIP, err.Error())
		return
	}

	// Validate threat type
	if err := ValidateThreat(req.Threat); err != nil {
		BadRequestWithCode(c, ErrInvalidThreatType, err.Error())
		return
	}

	// Validate reason
	if err := ValidateReason(req.Reason); err != nil {
		BadRequestWithCode(c, ErrInvalidRequest, err.Error())
		return
	}

	// Validate duration
	if err := ValidateDuration(req.DurationHours); err != nil {
		BadRequestWithCode(c, ErrInvalidDuration, err.Error())
		return
	}

	ctx := c.Request.Context()

	blockedIP := models.BlockedIP{
		IPAddress:   validatedIP,
		Description: req.Threat,
		Reason:      req.Reason,
		Permanent:   req.Permanent || req.DurationHours == -1,
		URL:         req.URL,
		UserAgent:   req.UserAgent,
		Payload:     req.Payload,
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

	// Get severity from the rule in the database
	severity := GetRuleSeverity(ruleService, req.Threat)

	if err == nil && existingBlock != nil {
		// Update existing block
		blockedIP.ID = existingBlock.ID
		if err := blocklistService.UpdateBlockedIP(ctx, &blockedIP); err != nil {
			InternalServerErrorWithCode(c, ErrDatabaseError, "Failed to update blocked IP")
			return
		}

		c.JSON(200, gin.H{
			"message": "IP block updated successfully",
			"entry":   blockedIP,
		})
	} else {
		// Create new block
		if err := blocklistService.BlockIP(ctx, &blockedIP); err != nil {
			InternalServerErrorWithCode(c, ErrDatabaseError, "Failed to create blocked IP")
			return
		}

		// Fetch the created block to get the actual stored values
		createdBlock, err := blocklistService.GetBlockedIPByIPAndDescription(ctx, validatedIP, req.Threat)
		if err != nil || createdBlock == nil {
			InternalServerErrorWithCode(c, ErrDatabaseError, "Failed to retrieve created block")
			return
		}

		// Emit blocking event to SIEM
		userEmail, _ := c.Get("user_email")
		userEmailStr := "unknown"
		if ue, ok := userEmail.(string); ok {
			userEmailStr = ue
		}

		emitBlockedIPEvent(req.IP, req.Threat, severity, req.Threat, req.Reason, durationStr, userEmailStr, c.ClientIP(), "success")

		c.JSON(201, gin.H{
			"message": "IP blocked successfully",
			"entry":   createdBlock,
		})
	}
}

// UnblockIPWithService - Unblocks an IP for a specific rule/description
func UnblockIPWithService(blocklistService *service.BlocklistService, logService *service.LogService, ruleService *service.RuleService, c *gin.Context) {
	ip := c.Param("ip")
	threat := c.Query("threat") // Get rule name from query string

	if threat == "" {
		BadRequestWithCode(c, ErrMissingField, "threat parameter required")
		return
	}

	ctx := c.Request.Context()

	// Find and delete the block
	blockedIP, err := blocklistService.GetBlockedIPByIPAndDescription(ctx, ip, threat)
	if err != nil || blockedIP == nil {
		NotFoundWithCode(c, ErrIPNotFound, "Blocked IP entry not found")
		return
	}

	if err := blocklistService.UnblockIP(ctx, ip); err != nil {
		InternalServerErrorWithCode(c, ErrDatabaseError, "Failed to delete blocked IP")
		return
	}

	// Emit unblocking event to SIEM
	userEmail, _ := c.Get("user_email")
	userEmailStr := "unknown"
	if ue, ok := userEmail.(string); ok {
		userEmailStr = ue
	}

	severity := GetRuleSeverity(ruleService, threat)
	emitUnblockedIPEvent(ip, threat, severity, threat, userEmailStr, c.ClientIP(), "success")

	// Log to WAF logs using data from the database BlockedIP record
	logUnblockToWAF(ip, threat, severity, blockedIP.URL, blockedIP.UserAgent, blockedIP.Payload)

	c.JSON(200, gin.H{"message": "IP unblocked successfully", "ip": ip, "threat": threat})
}

// UnblockIP - Deprecated: use NewUnblockIPHandler instead
func UnblockIP(c *gin.Context) {
	BadRequest(c, "use NewUnblockIPHandler")
}


// IsIPBlocked - Checks if an IP is blocked for a specific rule/description in the database
// Note: This function is deprecated and should use BlocklistService instead
func IsIPBlocked(blocklistService *service.BlocklistService, ip string, description string) bool {
	ctx := context.Background()
	_, err := blocklistService.GetBlockedIPByIPAndDescription(ctx, ip, description)
	return err == nil
}

// NewGetBlocklistForWAF godoc
// @Summary Get blocklist for WAF
// @Description Returns blocklist for WAF (public endpoint, no auth required)
// @Tags Blocklist
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{} "Blocklist data"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /blocklist/waf [get]
func NewGetBlocklistForWAF(blocklistService *service.BlocklistService) func(*gin.Context) {
	return func(c *gin.Context) {
		ctx := c.Request.Context()

		blockedIPs, err := blocklistService.GetActiveBlockedIPs(ctx)
		if err != nil {
			InternalServerErrorWithCode(c, ErrServiceError, "Failed to fetch blocked IPs")
			return
		}

		response := dto.NewStandardListResponse(blockedIPs, len(blockedIPs))
		c.JSON(200, response)
	}
}

// NewGetWhitelistForWAF godoc
// @Summary Get whitelist for WAF
// @Description Returns whitelist for WAF (public endpoint, no auth required)
// @Tags Whitelist
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{} "Whitelist data"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /whitelist/waf [get]
func NewGetWhitelistForWAF(whitelistService *service.WhitelistService) func(*gin.Context) {
	return func(c *gin.Context) {
		ctx := c.Request.Context()

		whitelisted, err := whitelistService.GetAllWhitelistedIPs(ctx)
		if err != nil {
			InternalServerErrorWithCode(c, ErrServiceError, "Failed to fetch whitelist")
			return
		}

		response := dto.NewStandardListResponse(whitelisted, len(whitelisted))
		c.JSON(200, response)
	}
}

// GetRuleSeverity retrieves the severity from the rule in the database
// Falls back to GetSeverityFromThreatType if rule not found
func GetRuleSeverity(ruleService *service.RuleService, ruleName string) string {
	ctx := context.Background()

	// Try to find the rule by name
	allRules, err := ruleService.GetAllRules(ctx)
	if err != nil {
		// Fall back to deriving severity from threat type
		return GetSeverityFromThreatType(ruleName)
	}

	for _, rule := range allRules {
		if rule.Name == ruleName {
			if rule.Severity != "" {
				return rule.Severity
			}
		}
	}

	// Fall back to deriving severity from threat type if not found
	return GetSeverityFromThreatType(ruleName)
}

// emitBlockedIPEvent emits a blocking event to the SIEM via log file
func emitBlockedIPEvent(ip, threatType, severity, description, reason, duration, operator, operatorIP, status string) {
	// Create logs directory if it doesn't exist
	logsDir := "/var/log/caddy"
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		logger.Log.WithError(err).Error("Failed to create logs directory")
		return
	}

	// Initialize event logger for blocked IP events
	eventLogPath := logsDir + "/blocked_ip_events.log"
	eventLogger, err := logger.NewEventLogger(eventLogPath)
	if err != nil {
		logger.Log.WithError(err).Error("Failed to initialize event logger")
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
		logger.Log.WithError(err).Error("Failed to log blocked IP event")
		return
	}

	logger.Log.WithFields(map[string]interface{}{
		"ip":       ip,
		"threat":   threatType,
		"duration": duration,
	}).Info("Blocked IP event emitted")
}

// emitUnblockedIPEvent emits an unblocking event to the SIEM via log file
func emitUnblockedIPEvent(ip, threatType, severity, description, operator, operatorIP, status string) {
	// Create logs directory if it doesn't exist
	logsDir := "/var/log/caddy"
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		logger.Log.WithError(err).Error("Failed to create logs directory")
		return
	}

	// Initialize event logger for blocked IP events
	eventLogPath := logsDir + "/blocked_ip_events.log"
	eventLogger, err := logger.NewEventLogger(eventLogPath)
	if err != nil {
		logger.Log.WithError(err).Error("Failed to initialize event logger")
		return
	}
	defer eventLogger.Close()

	// Create the event with all available fields
	event := logger.BlockedIPEvent{
		Timestamp:   time.Now(),
		EventType:   "ip_unblocked_manual",
		IP:          ip,
		ThreatType:  threatType,
		Severity:    severity,
		Description: description,
		Reason:      "Manually unblocked",
		Duration:    "unblocked",
		Operator:    operator,
		OperatorIP:  operatorIP,
		Status:      status,
	}

	// Log the event
	if err := eventLogger.LogBlockedIPEvent(event); err != nil {
		logger.Log.WithError(err).Error("Failed to log unblocked IP event")
		return
	}

	logger.Log.WithFields(map[string]interface{}{
		"ip":     ip,
		"threat": threatType,
	}).Info("Unblocked IP event emitted")
}

// logUnblockToWAF logs a manual unblock event to WAF log files
func logUnblockToWAF(ip, threat, severity, url, userAgent, payload string) {
	logsDir := "/var/log/caddy"
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		logger.Log.WithError(err).Warn("Failed to create logs directory")
		return
	}

	// Write to both WAN and LAN log files
	logFiles := []string{
		logsDir + "/waf_wan.log",
		logsDir + "/waf_lan.log",
	}

	for _, logFilePath := range logFiles {
		wafLogger, err := logger.NewWAFLogger(logFilePath)
		if err != nil {
			logger.Log.WithFields(map[string]interface{}{
				"path": logFilePath,
			}).WithError(err).Warn("Failed to initialize WAF logger")
			continue
		}
		defer wafLogger.Close()

		entry := logger.LogEntry{
			Timestamp:       time.Now(),
			ThreatType:      threat,
			Severity:        severity,
			Description:     threat,
			ClientIP:        ip,
			ClientIPSource:  "manual-unblock",
			Method:          "MANUAL_UNBLOCK",
			URL:             url,
			UserAgent:       userAgent,
			Payload:         payload,
			Blocked:         false,
			BlockedBy:       "manual",
		}

		if err := wafLogger.Log(entry); err != nil {
			logger.Log.WithFields(map[string]interface{}{
				"path": logFilePath,
			}).WithError(err).Warn("Failed to log manual unblock to WAF file")
		}
	}
}