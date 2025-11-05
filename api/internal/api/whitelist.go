package api

import (
	"fmt"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"gorm.io/gorm"
)

// GetWhitelist - Ritorna la lista degli IP whitelisted
func NewGetWhitelistHandler(db *gorm.DB) gin.HandlerFunc {
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

// AddToWhitelist - Aggiunge un IP alla whitelist
func NewAddToWhitelistHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			IPAddress string `json:"ip_address" binding:"required"`
			Reason    string `json:"reason"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": "Invalid request"})
			return
		}

		whitelist := models.WhitelistedIP{
			IPAddress: req.IPAddress,
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
		db.First(&whitelistEntry, uint(idUint))
		ipAddr := whitelistEntry.IPAddress

		if err := db.Delete(&models.WhitelistedIP{}, uint(idUint)).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				c.JSON(404, gin.H{"error": "Entry not found"})
			} else {
						c.JSON(500, gin.H{"error": "failed to remove from whitelist"})
			}
			return
		}

		// Log this action
		userID, _ := c.Get("user_id")
		userEmail, _ := c.Get("user_email")
		LogAuditAction(db, userID.(uint), userEmail.(string), "REMOVE_WHITELIST", "WHITELIST",
			"ip", ipAddr, fmt.Sprintf("Removed IP %s from whitelist", ipAddr),
			map[string]interface{}{"ip": ipAddr}, c.ClientIP())

		c.JSON(200, gin.H{"message": "IP removed from whitelist successfully"})
	}
}

// IsIPWhitelisted - Controlla se un IP è whitelisted
func IsIPWhitelisted(db *gorm.DB, ip string) bool {
	var count int64
	db.Model(&models.WhitelistedIP{}).Where("ip_address = ?", ip).Count(&count)
	return count > 0
}
