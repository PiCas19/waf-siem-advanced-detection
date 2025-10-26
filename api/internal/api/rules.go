package api

import (
	"fmt"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type WAFRule struct {
	ID        string    `json:"id" gorm:"primaryKey"`
	Name      string    `json:"name" gorm:"index"`
	Pattern   string    `json:"pattern"`
	Description string  `json:"description"`
	ThreatType string   `json:"threat_type" gorm:"index"`
	Mode      string    `json:"mode"` // "block" or "detect"
	Enabled   bool      `json:"enabled" gorm:"index"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type BlockedIP struct {
	ID        string    `json:"id" gorm:"primaryKey"`
	IP        string    `json:"ip" gorm:"uniqueIndex"`
	Reason    string    `json:"reason"`
	BlockedAt time.Time `json:"blocked_at"`
	ExpiresAt *time.Time `json:"expires_at"`
	Permanent bool      `json:"permanent"`
}

var (
	rulesMu   sync.RWMutex
	rules     = make([]WAFRule, 0)
	blockedMu sync.RWMutex
	blockedIPs = make(map[string]BlockedIP)
)

// GetRules - Ritorna tutte le regole WAF
func GetRules(c *gin.Context) {
	rulesMu.RLock()
	defer rulesMu.RUnlock()

	c.JSON(200, gin.H{
		"rules": rules,
		"count": len(rules),
	})
}

// CreateRule - Crea una nuova regola WAF
func CreateRule(c *gin.Context) {
	var rule WAFRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		fmt.Printf("[ERROR] Failed to parse rule: %v\n", err)
		c.JSON(400, gin.H{"error": "Invalid rule data"})
		return
	}

	if rule.Name == "" || rule.Pattern == "" {
		c.JSON(400, gin.H{"error": "Name and Pattern are required"})
		return
	}

	rule.ID = fmt.Sprintf("rule_%d", time.Now().UnixNano())
	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()
	rule.Enabled = true

	rulesMu.Lock()
	rules = append(rules, rule)
	rulesMu.Unlock()

	fmt.Printf("[INFO] Rule created: ID=%s, Name=%s, ThreatType=%s, Mode=%s\n", rule.ID, rule.Name, rule.ThreatType, rule.Mode)

	c.JSON(201, gin.H{
		"message": "Rule created successfully",
		"rule": rule,
	})
}

// UpdateRule - Modifica una regola esistente
func UpdateRule(c *gin.Context) {
	ruleID := c.Param("id")

	var updatedRule WAFRule
	if err := c.ShouldBindJSON(&updatedRule); err != nil {
		c.JSON(400, gin.H{"error": "Invalid rule data"})
		return
	}

	rulesMu.Lock()
	defer rulesMu.Unlock()

	for i, rule := range rules {
		if rule.ID == ruleID {
			rules[i].Name = updatedRule.Name
			rules[i].Pattern = updatedRule.Pattern
			rules[i].Description = updatedRule.Description
			rules[i].ThreatType = updatedRule.ThreatType
			rules[i].Mode = updatedRule.Mode
			rules[i].UpdatedAt = time.Now()

			fmt.Printf("[INFO] Rule updated: ID=%s, Name=%s\n", ruleID, updatedRule.Name)

			c.JSON(200, gin.H{
				"message": "Rule updated successfully",
				"rule": rules[i],
			})
			return
		}
	}

	c.JSON(404, gin.H{"error": "Rule not found"})
}

// DeleteRule - Elimina una regola
func DeleteRule(c *gin.Context) {
	ruleID := c.Param("id")

	rulesMu.Lock()
	defer rulesMu.Unlock()

	for i, rule := range rules {
		if rule.ID == ruleID {
			rules = append(rules[:i], rules[i+1:]...)
			fmt.Printf("[INFO] Rule deleted: ID=%s\n", ruleID)
			c.JSON(200, gin.H{"message": "Rule deleted successfully"})
			return
		}
	}

	c.JSON(404, gin.H{"error": "Rule not found"})
}

// ToggleRule - Abilita/Disabilita una regola
func ToggleRule(c *gin.Context) {
	ruleID := c.Param("id")

	rulesMu.Lock()
	defer rulesMu.Unlock()

	for i, rule := range rules {
		if rule.ID == ruleID {
			rules[i].Enabled = !rules[i].Enabled
			rules[i].UpdatedAt = time.Now()

			fmt.Printf("[INFO] Rule toggled: ID=%s, Enabled=%v\n", ruleID, rules[i].Enabled)

			c.JSON(200, gin.H{
				"message": "Rule toggled successfully",
				"enabled": rules[i].Enabled,
			})
			return
		}
	}

	c.JSON(404, gin.H{"error": "Rule not found"})
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
		fmt.Printf("[WARN] IP already blocked: %s, Updating reason\n", req.IP)
		existing.Reason = req.Reason
		existing.Permanent = req.Permanent
		existing.UpdatedAt = time.Now()
		blockedIPs[req.IP] = existing

		c.JSON(200, gin.H{
			"message": "IP already blocked, reason updated",
			"ip": req.IP,
		})
		return
	}

	// Crea nuovo record di blocco
	blockedIP := BlockedIP{
		ID:        fmt.Sprintf("block_%d", time.Now().UnixNano()),
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

	fmt.Printf("[SECURITY] IP Blocked: %s, Reason: %s, Permanent: %v\n", req.IP, req.Reason, req.Permanent)

	c.JSON(201, gin.H{
		"message": "IP blocked successfully",
		"ip": req.IP,
		"blocked": blockedIP,
	})
}

// GetBlocklist - Ritorna la lista degli IP bloccati
func GetBlocklist(c *gin.Context) {
	blockedMu.RLock()
	defer blockedMu.RUnlock()

	blockedIPs := make([]BlockedIP, 0)
	now := time.Now()

	// Filtra IP non scaduti
	for _, ip := range blockedIPs {
		if ip.Permanent || (ip.ExpiresAt != nil && ip.ExpiresAt.After(now)) {
			blockedIPs = append(blockedIPs, ip)
		}
	}

	c.JSON(200, gin.H{
		"blocked_ips": blockedIPs,
		"count": len(blockedIPs),
	})
}

// UnblockIP - Sblocca un IP
func UnblockIP(c *gin.Context) {
	ip := c.Param("ip")

	blockedMu.Lock()
	defer blockedMu.Unlock()

	if _, exists := blockedIPs[ip]; exists {
		delete(blockedIPs, ip)
		fmt.Printf("[SECURITY] IP Unblocked: %s\n", ip)
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

// GetRulesByThreatType - Ritorna le regole per un tipo di minaccia specifico
func GetRulesByThreatType(threatType string) []WAFRule {
	rulesMu.RLock()
	defer rulesMu.RUnlock()

	var matchingRules []WAFRule
	for _, rule := range rules {
		if rule.ThreatType == threatType && rule.Enabled {
			matchingRules = append(matchingRules, rule)
		}
	}

	return matchingRules
}
