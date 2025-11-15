package api

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/logger"
)

// GetBlocklist - Ritorna la lista degli IP bloccati da database
func GetBlocklist(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var blockedIPs []models.BlockedIP
		now := time.Now()

		// Recupera IP bloccati non scaduti dal database
		if err := db.Where("permanent = ? OR expires_at > ?", true, now).
			Find(&blockedIPs).Error; err != nil {
			c.JSON(500, gin.H{"error": "Failed to fetch blocked IPs"})
			return
		}

		c.JSON(200, gin.H{
			"blocked_ips": blockedIPs,
			"count":       len(blockedIPs),
		})
	}
}

// NewBlockIPHandler - Factory function per creare un handler per bloccare IP
func NewBlockIPHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		BlockIPWithDB(db, c)
	}
}

// NewUnblockIPHandler - Factory function per creare un handler per sbloccare IP
func NewUnblockIPHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		UnblockIPWithDB(db, c)
	}
}

// BlockIPWithDB - Blocca un IP per una specifica regola/descrizione
func BlockIPWithDB(db *gorm.DB, c *gin.Context) {
	var req struct {
		IP            string `json:"ip" binding:"required"`
		Threat        string `json:"threat" binding:"required"` // Nome della regola/descrizione (es: "Detect API Enumeration", "XSS")
		Reason        string `json:"reason" binding:"required"`
		Permanent     bool   `json:"permanent"`
		DurationHours int    `json:"duration_hours"` // Custom duration in hours (-1 for permanent)
	}

	// Note: The JSON tag "duration_hours" is already correct above!
	// This maps snake_case JSON field to Go field automatically

	if err := c.ShouldBindJSON(&req); err != nil {
		// Log failed block attempt - invalid request
		userID, _ := c.Get("user_id")
		userEmail, _ := c.Get("user_email")
		LogAuditActionWithError(db, userID.(uint), userEmail.(string), "BLOCK_IP", "BLOCKLIST",
			"ip", "unknown", "Failed to block IP - invalid request format", nil, c.ClientIP(), err.Error())
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	// Validate IP address
	validatedIP, err := ValidateIP(req.IP)
	if err != nil {
		userID, _ := c.Get("user_id")
		userEmail, _ := c.Get("user_email")
		LogAuditActionWithError(db, userID.(uint), userEmail.(string), "BLOCK_IP", "BLOCKLIST",
			"ip", req.IP, "Invalid IP address", nil, c.ClientIP(), err.Error())
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Validate threat type
	if err := ValidateThreat(req.Threat); err != nil {
		userID, _ := c.Get("user_id")
		userEmail, _ := c.Get("user_email")
		LogAuditActionWithError(db, userID.(uint), userEmail.(string), "BLOCK_IP", "BLOCKLIST",
			"ip", req.IP, "Invalid threat type", nil, c.ClientIP(), err.Error())
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Validate reason
	if err := ValidateReason(req.Reason); err != nil {
		userID, _ := c.Get("user_id")
		userEmail, _ := c.Get("user_email")
		LogAuditActionWithError(db, userID.(uint), userEmail.(string), "BLOCK_IP", "BLOCKLIST",
			"ip", req.IP, "Invalid reason", nil, c.ClientIP(), err.Error())
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Validate duration
	if err := ValidateDuration(req.DurationHours); err != nil {
		userID, _ := c.Get("user_id")
		userEmail, _ := c.Get("user_email")
		LogAuditActionWithError(db, userID.(uint), userEmail.(string), "BLOCK_IP", "BLOCKLIST",
			"ip", req.IP, "Invalid duration", nil, c.ClientIP(), err.Error())
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Controlla se esiste già un blocco per questo IP + descrizione
	var existingBlock models.BlockedIP
	blockExists := db.Where("ip_address = ? AND description = ?", validatedIP, req.Threat).
		First(&existingBlock).Error == nil

	blockedIP := models.BlockedIP{
		IPAddress:   validatedIP,
		Description: req.Threat,
		Reason:      req.Reason,
		Permanent:   req.Permanent || req.DurationHours == -1,
	}

	// Calcola la scadenza in base alla duration
	if !blockedIP.Permanent && req.DurationHours > 0 {
		expiresAt := time.Now().Add(time.Duration(int64(req.DurationHours)) * time.Hour)
		blockedIP.ExpiresAt = &expiresAt
	} else if !blockedIP.Permanent {
		// Fallback: default 24 ore
		expiresAt := time.Now().Add(24 * time.Hour)
		blockedIP.ExpiresAt = &expiresAt
	}

	// Se esiste, aggiorna; altrimenti crea
	userID, _ := c.Get("user_id")
	userEmail, _ := c.Get("user_email")

	if blockExists {
		if err := db.Model(&existingBlock).Updates(blockedIP).Error; err != nil {
			// Log failed block update - database error
			LogAuditActionWithError(db, userID.(uint), userEmail.(string), "BLOCK_IP", "BLOCKLIST",
				"ip", req.IP, "Failed to update IP block in database", nil, c.ClientIP(), err.Error())
			c.JSON(500, gin.H{"error": "Failed to update blocked IP", "details": err.Error()})
			return
		}
		// Ricarica l'entry aggiornata dal database
		db.First(&existingBlock)

		// Log successful block update
		durationStr := "temporary"
		if blockedIP.Permanent {
			durationStr = "permanent"
		} else if req.DurationHours > 0 {
			durationStr = fmt.Sprintf("%d hours", req.DurationHours)
		}
		details := map[string]interface{}{
			"ip":          req.IP,
			"threat_type": req.Threat,
			"reason":      req.Reason,
			"duration":    durationStr,
		}
		LogAuditAction(db, userID.(uint), userEmail.(string), "BLOCK_IP_UPDATE", "BLOCKLIST",
			"ip", req.IP, fmt.Sprintf("Updated IP block for %s (threat: %s)", req.IP, req.Threat),
			details, c.ClientIP())

		c.JSON(200, gin.H{
			"message": "IP block updated successfully",
			"entry":   existingBlock,
		})
	} else {
		if err := db.Create(&blockedIP).Error; err != nil {
			// Log failed block creation - database error
			LogAuditActionWithError(db, userID.(uint), userEmail.(string), "BLOCK_IP", "BLOCKLIST",
				"ip", req.IP, "Failed to create IP block in database", nil, c.ClientIP(), err.Error())
			c.JSON(500, gin.H{"error": "Failed to create blocked IP", "details": err.Error()})
			return
		}

		// Log this action
		durationStr := "temporary"
		if blockedIP.Permanent {
			durationStr = "permanent"
		} else if req.DurationHours > 0 {
			durationStr = fmt.Sprintf("%d hours", req.DurationHours)
		}
		details := map[string]interface{}{
			"ip":          req.IP,
			"threat_type": req.Threat,
			"reason":      req.Reason,
			"duration":    durationStr,
		}
		LogAuditAction(db, userID.(uint), userEmail.(string), "BLOCK_IP", "BLOCKLIST",
			"ip", req.IP, fmt.Sprintf("Blocked IP %s for threat: %s", req.IP, req.Threat),
			details, c.ClientIP())

		// Emit blocking event to SIEM
		emitBlockedIPEvent(req.IP, req.Threat, durationStr, userEmail.(string), c.ClientIP(), "success")

		c.JSON(201, gin.H{
			"message": "IP blocked successfully",
			"entry":   blockedIP,
		})
	}

	// Update logs for this IP AND descrizione, marca come bloccato manualmente
	if err := db.Model(&models.Log{}).
		Where("client_ip = ? AND description = ?", req.IP, req.Threat).
		Updates(map[string]interface{}{
			"blocked":    true,
			"blocked_by": "manual",
		}).Error; err != nil {
		// Log the error but don't fail the request
		c.JSON(500, gin.H{"error": "Failed to update logs", "details": err.Error()})
		return
	}
}

// UnblockIPWithDB - Sblocca un IP per una specifica regola/descrizione
func UnblockIPWithDB(db *gorm.DB, c *gin.Context) {
	ip := c.Param("ip")
	threat := c.Query("threat") // Ottieni il nome della regola dalla query string

	userID, _ := c.Get("user_id")
	userEmail, _ := c.Get("user_email")

	if threat == "" {
		// Log failed unblock attempt - missing threat parameter
		LogAuditActionWithError(db, userID.(uint), userEmail.(string), "UNBLOCK_IP", "BLOCKLIST",
			"ip", ip, "Failed to unblock IP - threat parameter missing", nil, c.ClientIP(), "threat parameter required")
		c.JSON(400, gin.H{"error": "threat parameter required"})
		return
	}

	// Elimina il blocco dal database
	if err := db.Where("ip_address = ? AND description = ?", ip, threat).
		Delete(&models.BlockedIP{}).Error; err != nil {
		// Log failed unblock attempt - database error
		LogAuditActionWithError(db, userID.(uint), userEmail.(string), "UNBLOCK_IP", "BLOCKLIST",
			"ip", ip, fmt.Sprintf("Failed to unblock IP %s for threat %s", ip, threat), nil, c.ClientIP(), err.Error())
		c.JSON(500, gin.H{"error": "Failed to delete blocked IP", "details": err.Error()})
		return
	}

	// Log this unblock action
	details := map[string]interface{}{
		"ip":          ip,
		"threat_type": threat,
	}
	LogAuditAction(db, userID.(uint), userEmail.(string), "UNBLOCK_IP", "BLOCKLIST",
		"ip", ip, fmt.Sprintf("Unblocked IP %s for threat: %s", ip, threat),
		details, c.ClientIP())

	// Update logs for this IP AND descrizione to remove "manual" BlockedBy status
	// For default threats (XSS, SQLi, etc.), restore blocked_by="auto" since they're always blocked by rules
	// For custom rules, set blocked_by="" and blocked=false
	defaultThreats := []string{"XSS", "SQL_INJECTION", "LFI", "RFI", "COMMAND_INJECTION",
		"XXE", "LDAP_INJECTION", "SSTI", "HTTP_RESPONSE_SPLITTING", "PROTOTYPE_POLLUTION",
		"PATH_TRAVERSAL", "SSRF", "NOSQL_INJECTION"}

	// Check if this is a default threat
	isDefault := false
	for _, dt := range defaultThreats {
		if threat == dt {
			isDefault = true
			break
		}
	}

	if isDefault {
		// For default threats, restore blocked_by="auto"
		if err := db.Model(&models.Log{}).
			Where("client_ip = ? AND description = ? AND blocked_by = ?", ip, threat, "manual").
			Update("blocked_by", "auto").Error; err != nil {
			c.JSON(500, gin.H{"error": "Failed to update logs", "details": err.Error()})
			return
		}
	} else {
		// For custom rules, set blocked_by="" and blocked=false
		if err := db.Model(&models.Log{}).
			Where("client_ip = ? AND description = ? AND blocked_by = ?", ip, threat, "manual").
			Updates(map[string]interface{}{
				"blocked":    false,
				"blocked_by": "",
			}).Error; err != nil {
			c.JSON(500, gin.H{"error": "Failed to update logs", "details": err.Error()})
			return
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
func refreshStatsOnClients(db *gorm.DB) {
	// Nota: Il WebSocket viene usato per notificare i client, ma il valore
	// di stats aggiornato verrà fetched dal frontend da /api/stats endpoint
	// che legge direttamente dal database
}

// IsIPBlocked - Controlla se un IP è bloccato per una specifica regola/descrizione nel database
func IsIPBlocked(db *gorm.DB, ip string, description string) bool {
	var blockedIP models.BlockedIP
	now := time.Now()

	// Controlla se esiste un blocco non scaduto per questo IP + descrizione
	err := db.Where("ip_address = ? AND description = ? AND (permanent = ? OR expires_at > ?)",
		ip, description, true, now).First(&blockedIP).Error

	return err == nil
}

// NewGetBlocklistForWAF - Endpoint per il WAF per fetcare la lista degli IP bloccati
// Public endpoint (no auth required) - WAF needs to fetch this frequently
func NewGetBlocklistForWAF(db *gorm.DB) func(*gin.Context) {
	return func(c *gin.Context) {
		var blockedIPs []models.BlockedIP
		now := time.Now()

		// Recupera IP bloccati non scaduti dal database
		if err := db.Where("permanent = ? OR expires_at > ?", true, now).
			Find(&blockedIPs).Error; err != nil {
			c.JSON(500, gin.H{"error": "Failed to fetch blocked IPs"})
			return
		}

		c.JSON(200, gin.H{
			"blocked_ips": blockedIPs,
			"count":       len(blockedIPs),
		})
	}
}

// NewGetWhitelistForWAF - Endpoint per il WAF per fetcare la lista degli IP whitelisted
// Public endpoint (no auth required) - WAF needs to fetch this frequently
func NewGetWhitelistForWAF(db *gorm.DB) func(*gin.Context) {
	return func(c *gin.Context) {
		var whitelisted []models.WhitelistedIP
		if err := db.Order("created_at DESC").Find(&whitelisted).Error; err != nil {
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