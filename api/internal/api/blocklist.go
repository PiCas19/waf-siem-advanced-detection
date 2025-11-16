package api

import (
	"context"
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
		emitBlockedIPEvent(req.IP, req.Threat, durationStr, userEmailStr, c.ClientIP(), "success")

		c.JSON(201, gin.H{
			"message": "IP blocked successfully",
			"entry":   blockedIP,
		})
	}

	// Update logs for this IP and threat type to mark as manually blocked
	updates := map[string]interface{}{
		"blocked":    true,
		"blocked_by": "manual",
	}
	if err := logService.UpdateLogsByIPAndDescription(ctx, validatedIP, req.Threat, updates); err != nil {
		// Log the error but don't fail the request - block was already created successfully
		fmt.Println("Warning: Failed to update logs for blocked IP:", err)
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

	// Update logs for this IP and threat type to remove "manual" BlockedBy status
	// For default threats (XSS, SQLi, etc.), restore blocked_by="auto" since they're always blocked by rules
	// For custom rules, set blocked_by="" and blocked=false
	defaultThreats := []string{"XSS", "SQL_INJECTION", "LFI", "RFI", "COMMAND_INJECTION",
		"XXE", "LDAP_INJECTION", "SSTI", "HTTP_RESPONSE_SPLITTING", "PROTOTYPE_POLLUTION",
		"PATH_TRAVERSAL", "SSRF", "NOSQL_INJECTION"}

	isDefault := false
	for _, dt := range defaultThreats {
		if threat == dt {
			isDefault = true
			break
		}
	}

	if isDefault {
		// For default threats, restore blocked_by="auto"
		updates := map[string]interface{}{"blocked_by": "auto"}
		if err := logService.UpdateLogsByIPAndDescription(ctx, ip, threat, updates); err != nil {
			// Log the error but don't fail the request - IP was already unblocked successfully
			fmt.Println("Warning: Failed to update logs for unblocked IP:", err)
		}
	} else {
		// For custom rules, set blocked_by="" and blocked=false
		updates := map[string]interface{}{
			"blocked":    false,
			"blocked_by": "",
		}
		if err := logService.UpdateLogsByIPAndDescription(ctx, ip, threat, updates); err != nil {
			// Log the error but don't fail the request - IP was already unblocked successfully
			fmt.Println("Warning: Failed to update logs for unblocked IP:", err)
		}
	}

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
func emitBlockedIPEvent(ip, threatType, duration, operator, operatorIP, status string) {
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

	// Create the event
	event := logger.BlockedIPEvent{
		Timestamp:   time.Now(),
		EventType:   "ip_blocked_manual",
		IP:          ip,
		ThreatType:  threatType,
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