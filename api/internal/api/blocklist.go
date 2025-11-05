package api

import (
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
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
		Reason        string `json:"reason"`
		Permanent     bool   `json:"permanent"`
		DurationHours int    `json:"duration_hours"` // Custom duration in hours (-1 for permanent)
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	fmt.Printf("[DEBUG] BlockIP Request: IP=%s, Threat=%s, Permanent=%v, DurationHours=%d\n",
		req.IP, req.Threat, req.Permanent, req.DurationHours)

	// Controlla se esiste già un blocco per questo IP + descrizione
	var existingBlock models.BlockedIP
	blockExists := db.Where("ip_address = ? AND description = ?", req.IP, req.Threat).
		First(&existingBlock).Error == nil

	blockedIP := models.BlockedIP{
		IPAddress:   req.IP,
		Description: req.Threat,
		Reason:      req.Reason,
		Permanent:   req.Permanent || req.DurationHours == -1,
	}

	// Calcola la scadenza in base alla duration
	if !blockedIP.Permanent && req.DurationHours > 0 {
		expiresAt := time.Now().Add(time.Duration(req.DurationHours) * time.Hour)
		blockedIP.ExpiresAt = &expiresAt
		fmt.Printf("[DEBUG] Setting ExpiresAt: %v (in %d hours)\n", expiresAt, req.DurationHours)
	} else if !blockedIP.Permanent {
		// Fallback: default 24 ore
		expiresAt := time.Now().Add(24 * time.Hour)
		blockedIP.ExpiresAt = &expiresAt
		fmt.Printf("[DEBUG] Using default 24h expires: %v\n", expiresAt)
	} else {
		fmt.Printf("[DEBUG] Permanent block, no expiration\n")
	}

	// Se esiste, aggiorna; altrimenti crea
	if blockExists {
		if err := db.Model(&existingBlock).Updates(blockedIP).Error; err != nil {
			c.JSON(500, gin.H{"error": "Failed to update blocked IP", "details": err.Error()})
			return
		}
		c.JSON(200, gin.H{
			"message": "IP block updated successfully",
			"ip":      req.IP,
			"threat":  req.Threat,
		})
	} else {
		if err := db.Create(&blockedIP).Error; err != nil {
			c.JSON(500, gin.H{"error": "Failed to create blocked IP", "details": err.Error()})
			return
		}
		c.JSON(201, gin.H{
			"message": "IP blocked successfully",
			"ip":      req.IP,
			"threat":  req.Threat,
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

	if threat == "" {
		c.JSON(400, gin.H{"error": "threat parameter required"})
		return
	}

	// Elimina il blocco dal database
	if err := db.Where("ip_address = ? AND description = ?", ip, threat).
		Delete(&models.BlockedIP{}).Error; err != nil {
		c.JSON(500, gin.H{"error": "Failed to delete blocked IP", "details": err.Error()})
		return
	}

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