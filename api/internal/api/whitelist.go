package api

import (
	"fmt"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"gorm.io/gorm"
)

// GetWhitelist - Ritorna la lista degli IP whitelisted (only non-deleted)
func NewGetWhitelistHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		whitelisted := []models.WhitelistedIP{}
		// Query ONLY non-deleted entries (where deleted_at IS NULL)
		if err := db.Where("deleted_at IS NULL").Order("created_at DESC").Find(&whitelisted).Error; err != nil {
			fmt.Printf("[ERROR] Failed to fetch whitelist: %v\n", err)
			c.JSON(500, gin.H{"error": "failed to fetch whitelist"})
			return
		}
		fmt.Printf("[DEBUG] Whitelist found %d entries\n", len(whitelisted))
		for _, entry := range whitelisted {
			fmt.Printf("[DEBUG] IP: %s, Reason: %s, DeletedAt: %v\n", entry.IPAddress, entry.Reason, entry.DeletedAt)
		}
		c.JSON(200, gin.H{
			"whitelisted_ips": whitelisted,
			"count":           len(whitelisted),
		})
	}
}

// AddToWhitelist - Aggiunge un IP alla whitelist
func NewAddToWhitelistHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			IPAddress string `json:"ip_address" binding:"required"`
			Reason    string `json:"reason" binding:"required"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": "Invalid request"})
			return
		}

		// Validate IP address
		validatedIP, err := ValidateIP(req.IPAddress)
		if err != nil {
			userID, _ := c.Get("user_id")
			userEmail, _ := c.Get("user_email")
			LogAuditActionWithError(db, userID.(uint), userEmail.(string), "ADD_WHITELIST", "WHITELIST",
				"ip", req.IPAddress, "Invalid IP address", nil, c.ClientIP(), err.Error())
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		// Validate reason
		if err := ValidateReason(req.Reason); err != nil {
			userID, _ := c.Get("user_id")
			userEmail, _ := c.Get("user_email")
			LogAuditActionWithError(db, userID.(uint), userEmail.(string), "ADD_WHITELIST", "WHITELIST",
				"ip", validatedIP, "Invalid reason", nil, c.ClientIP(), err.Error())
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		// Check if IP already exists in whitelist (including soft-deleted)
		var existingIP models.WhitelistedIP
		result := db.Unscoped().Where("ip_address = ?", validatedIP).First(&existingIP)
		if result.Error == nil {
			// IP already exists, restore it if soft-deleted and update the reason
			if err := db.Model(&existingIP).Update("deleted_at", nil).Error; err != nil {
				c.JSON(500, gin.H{"error": "failed to restore whitelist entry"})
				return
			}
			if err := db.Model(&existingIP).Update("reason", req.Reason).Error; err != nil {
				c.JSON(500, gin.H{"error": "failed to update whitelist entry"})
				return
			}
			// Reload the entry to get updated values
			if err := db.Unscoped().First(&existingIP, existingIP.ID).Error; err != nil {
				c.JSON(500, gin.H{"error": "failed to reload whitelist entry"})
				return
			}
			c.JSON(200, gin.H{
				"message": "Whitelist entry updated (IP already existed)",
				"entry":   existingIP,
			})
			return
		} else if result.Error != gorm.ErrRecordNotFound {
			// Some other error occurred
			c.JSON(500, gin.H{"error": "failed to check whitelist"})
			return
		}

		whitelist := models.WhitelistedIP{
			IPAddress: validatedIP,
			Reason:    req.Reason,
		}

		if err := db.Create(&whitelist).Error; err != nil {
			c.JSON(500, gin.H{"error": "failed to add to whitelist"})
			return
		}

		// Log this action
		userID, _ := c.Get("user_id")
		userEmail, _ := c.Get("user_email")
		details := map[string]interface{}{
			"ip":     req.IPAddress,
			"reason": req.Reason,
		}
		LogAuditAction(db, userID.(uint), userEmail.(string), "ADD_WHITELIST", "WHITELIST",
			"ip", req.IPAddress, fmt.Sprintf("Added IP %s to whitelist", req.IPAddress),
			details, c.ClientIP())

		c.JSON(201, gin.H{
			"message": "IP whitelisted successfully",
			"entry":   whitelist,
		})
	}
}

// RemoveFromWhitelist - Rimuove un IP dalla whitelist
func NewRemoveFromWhitelistHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		idUint, err := strconv.ParseUint(id, 10, 32)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid ID"})
			return
		}

		// Fetch IP address before deleting for logging
		var whitelistEntry models.WhitelistedIP
		if err := db.First(&whitelistEntry, uint(idUint)).Error; err != nil {
			c.JSON(404, gin.H{"error": "Whitelist entry not found"})
			return
		}

		if err := db.Delete(&whitelistEntry, uint(idUint)).Error; err != nil {
			c.JSON(500, gin.H{"error": "failed to remove from whitelist"})
			return
		}

		// Log this action
		userID, _ := c.Get("user_id")
		userEmail, _ := c.Get("user_email")
		LogAuditAction(db, userID.(uint), userEmail.(string), "REMOVE_WHITELIST", "WHITELIST",
			"ip", whitelistEntry.IPAddress, fmt.Sprintf("Removed IP %s from whitelist", whitelistEntry.IPAddress),
			nil, c.ClientIP())

		c.JSON(200, gin.H{"message": "IP removed from whitelist successfully"})
	}
}

// GetWhitelistForWAF - Ritorna la whitelist per il WAF (public endpoint)
func NewGetWhitelistForWAFHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var whitelisted []models.WhitelistedIP
		if err := db.Find(&whitelisted).Error; err != nil {
			c.JSON(500, gin.H{"error": "failed to fetch whitelist"})
			return
		}

		// Convert to simple map for WAF consumption
		whitelistMap := make(map[string]bool)
		for _, entry := range whitelisted {
			whitelistMap[entry.IPAddress] = true
		}

		c.JSON(200, gin.H{
			"whitelisted_ips": whitelistMap,
		})
	}
}
