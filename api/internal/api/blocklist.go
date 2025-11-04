package api

import (
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
)

// BlockedIP - IP bloccato dal WAF
type BlockedIP struct {
	ID        string    `json:"id" gorm:"primaryKey"`
	IP        string    `json:"ip" gorm:"uniqueIndex"`
	Reason    string    `json:"reason"`
	BlockedAt time.Time `json:"blocked_at"`
	ExpiresAt *time.Time `json:"expires_at"`
	Permanent bool      `json:"permanent"`
}

var (
	blockedMu sync.RWMutex
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

// BlockIPWithDB - Blocca un IP (aggiunge alla blocklist e aggiorna i log nel DB)
func BlockIPWithDB(db *gorm.DB, c *gin.Context) {
	var req struct {
		IP        string `json:"ip" binding:"required"`
		Reason    string `json:"reason"`
		Permanent bool   `json:"permanent"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	blockedMu.Lock()
	defer blockedMu.Unlock()

	// Se l'IP è già bloccato, aggiorna il record
	if existing, exists := blockedIPs[req.IP]; exists {
		existing.Reason = req.Reason
		existing.Permanent = req.Permanent
		blockedIPs[req.IP] = existing

		c.JSON(200, gin.H{
			"message": "IP already blocked, reason updated",
			"ip": req.IP,
		})
		return
	}

	// Crea nuovo record di blocco
	blockedIP := BlockedIP{
		ID:        req.IP,
		IP:        req.IP,
		Reason:    req.Reason,
		BlockedAt: time.Now(),
		Permanent: req.Permanent,
	}

	// Se non è permanente, imposta la scadenza a 24 ore
	if !req.Permanent {
		expiresAt := time.Now().Add(24 * time.Hour)
		blockedIP.ExpiresAt = &expiresAt
	}

	blockedIPs[req.IP] = blockedIP

	// Update all logs for this IP to set blocked=true and BlockedBy="manual"
	if err := db.Model(&models.Log{}).Where("client_ip = ?", req.IP).Updates(map[string]interface{}{
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

// UnblockIPWithDB - Sblocca un IP e ripristina lo status dei log
func UnblockIPWithDB(db *gorm.DB, c *gin.Context) {
	ip := c.Param("ip")

	blockedMu.Lock()
	defer blockedMu.Unlock()

	if _, exists := blockedIPs[ip]; exists {
		delete(blockedIPs, ip)

		// Update all logs for this IP to remove "manual" BlockedBy status
		// Set blocked=false and blocked_by="" since we're removing the manual block
		if err := db.Model(&models.Log{}).
			Where("client_ip = ? AND blocked_by = ?", ip, "manual").
			Updates(map[string]interface{}{
				"blocked": false,
				"blocked_by": "",
			}).Error; err != nil {
			c.JSON(500, gin.H{"error": "Failed to update logs", "details": err.Error()})
			return
		}

		c.JSON(200, gin.H{"message": "IP unblocked successfully"})
		return
	}

	c.JSON(404, gin.H{"error": "IP not found in blocklist"})
}

// UnblockIP - Deprecated: use NewUnblockIPHandler instead
func UnblockIP(c *gin.Context) {
	c.JSON(400, gin.H{"error": "use NewUnblockIPHandler"})
}

// IsIPBlocked - Controlla se un IP è bloccato
func IsIPBlocked(ip string) bool {
	blockedMu.RLock()
	defer blockedMu.RUnlock()

	if blockedIP, exists := blockedIPs[ip]; exists {
		// Se ha una scadenza, controlla se è ancora valida
		if blockedIP.ExpiresAt != nil {
			return blockedIP.ExpiresAt.After(time.Now())
		}
		// Se è permanente, sempre bloccato
		return blockedIP.Permanent || blockedIP.ExpiresAt == nil
	}

	return false
}