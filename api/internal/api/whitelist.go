package api

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/service"
	"gorm.io/gorm"
)

// NewGetWhitelistHandler - Returns the list of whitelisted IPs (only non-deleted)
func NewGetWhitelistHandler(whitelistService *service.WhitelistService) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()

		whitelisted, err := whitelistService.GetAllWhitelistedIPs(ctx)
		if err != nil {
			InternalServerErrorWithCode(c, ErrServiceError, "Failed to fetch whitelist")
			return
		}

		c.JSON(200, gin.H{
			"whitelisted_ips": whitelisted,
			"count":           len(whitelisted),
		})
	}
}

// NewAddToWhitelistHandler - Adds an IP to the whitelist
func NewAddToWhitelistHandler(whitelistService *service.WhitelistService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			IPAddress string `json:"ip_address" binding:"required"`
			Reason    string `json:"reason" binding:"required"`
		}

		if !ValidateJSON(c, &req) {
			return
		}

		// Validate IP address
		validatedIP, err := ValidateIP(req.IPAddress)
		if err != nil {
			BadRequestWithCode(c, ErrInvalidIP, err.Error())
			return
		}

		// Validate reason
		if err := ValidateReason(req.Reason); err != nil {
			BadRequestWithCode(c, ErrInvalidRequest, err.Error())
			return
		}

		ctx := c.Request.Context()

		whitelist := models.WhitelistedIP{
			IPAddress: validatedIP,
			Reason:    req.Reason,
		}

		// Check if IP already exists in whitelist (including soft-deleted)
		existingIP, err := whitelistService.CheckWhitelistedIPExists(ctx, validatedIP)

		if err == nil && existingIP != nil {
			// IP already exists, restore it if soft-deleted and update the reason
			existingIP.Reason = req.Reason
			existingIP.DeletedAt = gorm.DeletedAt{}
			if err := whitelistService.UpdateWhitelistedIP(ctx, existingIP); err != nil {
				InternalServerErrorWithCode(c, ErrDatabaseError, "Failed to update whitelist entry")
				return
			}

			c.JSON(200, gin.H{
				"message": "Whitelist entry updated (IP already existed)",
				"entry":   existingIP,
			})
		} else {
			// Create new whitelist entry
			if err := whitelistService.AddToWhitelist(ctx, &whitelist); err != nil {
				InternalServerErrorWithCode(c, ErrDatabaseError, "Failed to add to whitelist")
				return
			}

			c.JSON(201, gin.H{
				"message": "IP whitelisted successfully",
				"entry":   whitelist,
			})
		}
	}
}

// NewRemoveFromWhitelistHandler - Removes an IP from the whitelist
func NewRemoveFromWhitelistHandler(whitelistService *service.WhitelistService) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		idUint, err := strconv.ParseUint(id, 10, 32)
		if err != nil {
			BadRequestWithCode(c, ErrInvalidRequest, "Invalid ID")
			return
		}

		ctx := c.Request.Context()

		if err := whitelistService.RemoveFromWhitelist(ctx, uint(idUint)); err != nil {
			InternalServerErrorWithCode(c, ErrDatabaseError, "Failed to remove from whitelist")
			return
		}

		c.JSON(200, gin.H{"message": "IP removed from whitelist successfully"})
	}
}

// NewGetWhitelistForWAFHandler - Returns the whitelist for the WAF (public endpoint)
func NewGetWhitelistForWAFHandler(whitelistService *service.WhitelistService) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()

		whitelisted, err := whitelistService.GetAllWhitelistedIPs(ctx)
		if err != nil {
			InternalServerErrorWithCode(c, ErrServiceError, "Failed to fetch whitelist")
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
