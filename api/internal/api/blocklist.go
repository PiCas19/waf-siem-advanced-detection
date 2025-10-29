package api

import (
	"sync"
	"time"

	"github.com/gin-gonic/gin"
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

// BlockIP - Blocca un IP (aggiunge alla blocklist)
func BlockIP(c *gin.Context) {
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

	c.JSON(201, gin.H{
		"message": "IP blocked successfully",
		"ip": req.IP,
		"blocked": blockedIP,
	})
}

// UnblockIP - Sblocca un IP
func UnblockIP(c *gin.Context) {
	ip := c.Param("ip")

	blockedMu.Lock()
	defer blockedMu.Unlock()

	if _, exists := blockedIPs[ip]; exists {
		delete(blockedIPs, ip)
		c.JSON(200, gin.H{"message": "IP unblocked successfully"})
		return
	}

	c.JSON(404, gin.H{"error": "IP not found in blocklist"})
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

