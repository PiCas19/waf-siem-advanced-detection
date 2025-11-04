package api

import (
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
)

// BlockedIP - IP bloccato dal WAF per uno specifico tipo di minaccia
type BlockedIP struct {
	ID        string    `json:"id" gorm:"primaryKey"`
	IP        string    `json:"ip" gorm:"index"`
	ThreatType string   `json:"threat_type"` // Tipo di minaccia per cui l'IP è bloccato
	Reason    string    `json:"reason"`
	BlockedAt time.Time `json:"blocked_at"`
	ExpiresAt *time.Time `json:"expires_at"`
	Permanent bool      `json:"permanent"`
}

var (
	blockedMu sync.RWMutex
	// Mappa: "ip::threatType" -> BlockedIP (così possiamo avere lo stesso IP bloccato per minacce diverse)
	blockedIPs = make(map[string]BlockedIP)
)

// GetBlocklist - Ritorna la lista degli IP bloccati
func GetBlocklist(c *gin.Context) {
	blockedMu.RLock()
	defer blockedMu.RUnlock()

	result := make([]BlockedIP, 0)
	now := time.Now()

	// Filtra IP non scaduti
	for _, ip := range blockedIPs {
		if ip.Permanent || (ip.ExpiresAt != nil && ip.ExpiresAt.After(now)) {
			result = append(result, ip)
		}
	}

	c.JSON(200, gin.H{
		"blocked_ips": result,
		"count": len(result),
	})
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
		IP        string `json:"ip" binding:"required"`
		Threat    string `json:"threat" binding:"required"` // Nome della regola/minaccia (es: "Detect API Enumeration", "XSS")
		Reason    string `json:"reason"`
		Permanent bool   `json:"permanent"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	blockedMu.Lock()
	defer blockedMu.Unlock()

	// Chiave composita: "ip::threat" (dove threat è il nome della regola/descrizione)
	blockKey := req.IP + "::" + req.Threat

	// Se l'IP è già bloccato per questa regola, aggiorna il record
	if existing, exists := blockedIPs[blockKey]; exists {
		existing.Reason = req.Reason
		existing.Permanent = req.Permanent
		blockedIPs[blockKey] = existing

		c.JSON(200, gin.H{
			"message": "IP already blocked for this rule, reason updated",
			"ip": req.IP,
			"threat": req.Threat,
		})
		return
	}

	// Crea nuovo record di blocco per questo IP + regola
	blockedIP := BlockedIP{
		ID:         blockKey,
		IP:         req.IP,
		ThreatType: req.Threat, // Usa il campo ThreatType per memorizzare il nome della regola
		Reason:     req.Reason,
		BlockedAt:  time.Now(),
		Permanent:  req.Permanent,
	}

	// Se non è permanente, imposta la scadenza a 24 ore
	if !req.Permanent {
		expiresAt := time.Now().Add(24 * time.Hour)
		blockedIP.ExpiresAt = &expiresAt
	}

	blockedIPs[blockKey] = blockedIP

	// Update logs for this IP AND regola/descrizione, ma solo se non erano già bloccati da una regola
	if err := db.Model(&models.Log{}).
		Where("client_ip = ? AND description = ? AND (blocked_by = '' OR blocked_by IS NULL)", req.IP, req.Threat).
		Updates(map[string]interface{}{
			"blocked": true,
			"blocked_by": "manual",
		}).Error; err != nil {
		// Log the error but don't fail the request
		c.JSON(500, gin.H{"error": "Failed to update logs", "details": err.Error()})
		return
	}

	c.JSON(201, gin.H{
		"message": "IP blocked successfully",
		"ip": req.IP,
		"blocked": blockedIP,
	})
}

// UnblockIPWithDB - Sblocca un IP per una specifica regola/descrizione
func UnblockIPWithDB(db *gorm.DB, c *gin.Context) {
	ip := c.Param("ip")
	threat := c.Query("threat") // Ottieni il nome della regola dalla query string

	if threat == "" {
		c.JSON(400, gin.H{"error": "threat parameter required"})
		return
	}

	blockedMu.Lock()
	defer blockedMu.Unlock()

	// Chiave composita: "ip::threat"
	blockKey := ip + "::" + threat

	if _, exists := blockedIPs[blockKey]; exists {
		delete(blockedIPs, blockKey)

		// Update logs for this IP AND regola/descrizione to remove "manual" BlockedBy status
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
					"blocked": false,
					"blocked_by": "",
				}).Error; err != nil {
				c.JSON(500, gin.H{"error": "Failed to update logs", "details": err.Error()})
				return
			}
		}

		c.JSON(200, gin.H{"message": "IP unblocked successfully", "ip": ip, "threat": threat})
		return
	}

	c.JSON(404, gin.H{"error": "IP not found in blocklist"})
}

// UnblockIP - Deprecated: use NewUnblockIPHandler instead
func UnblockIP(c *gin.Context) {
	c.JSON(400, gin.H{"error": "use NewUnblockIPHandler"})
}

// IsIPBlocked - Controlla se un IP è bloccato per una specifica regola/descrizione
func IsIPBlocked(ip string, threat string) bool {
	blockedMu.RLock()
	defer blockedMu.RUnlock()

	// Chiave composita: "ip::threat"
	blockKey := ip + "::" + threat

	if blockedIP, exists := blockedIPs[blockKey]; exists {
		// Se è permanente, sempre bloccato
		if blockedIP.Permanent {
			return true
		}
		// Se ha una scadenza, controlla se è ancora valida
		if blockedIP.ExpiresAt != nil {
			return blockedIP.ExpiresAt.After(time.Now())
		}
		// Se nessuna delle due condizioni, non è bloccato
		return false
	}

	return false
}