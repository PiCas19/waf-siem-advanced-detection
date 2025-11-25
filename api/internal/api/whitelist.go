package api

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/dto"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/helpers"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/service"
	"gorm.io/gorm"
)

// NewGetWhitelistHandler godoc
// @Summary Get whitelisted IPs list
// @Description Returns paginated list of whitelisted IPs
// @Tags Whitelist
// @Accept json
// @Produce json
// @Param limit query int false "Number of items per page (default 20, max 100)" default(20)
// @Param offset query int false "Pagination offset (default 0)" default(0)
// @Param sort query string false "Sort field (id, ip_address, created_at)"
// @Param order query string false "Sort order (asc or desc)" default(asc)
// @Success 200 {object} dto.StandardPaginatedResponse{items=[]models.WhitelistedIP}
// @Failure 400 {object} map[string]interface{} "Invalid pagination parameters"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /whitelist [get]
// @Security BearerAuth
func NewGetWhitelistHandler(whitelistService *service.WhitelistService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Parse pagination parameters
		limit, offset, _, _, err := helpers.ParsePaginationParams(c)
		if err != nil {
			BadRequestWithCode(c, ErrInvalidRequest, err.Error())
			return
		}

		ctx := c.Request.Context()

		// Fetch paginated whitelisted IPs
		whitelisted, total, err := whitelistService.GetWhitelistedIPsPaginated(ctx, offset, limit)
		if err != nil {
			InternalServerErrorWithCode(c, ErrServiceError, "Failed to fetch whitelist")
			return
		}

		// Build paginated response
		response := helpers.BuildStandardPaginatedResponse(whitelisted, limit, offset, total)
		c.JSON(200, response)
	}
}

// NewAddToWhitelistHandler godoc
// @Summary Add IP to whitelist
// @Description Adds an IP address to the whitelist
// @Tags Whitelist
// @Accept json
// @Produce json
// @Param request body object{ip_address=string,reason=string} true "Whitelist entry"
// @Success 200 {object} map[string]interface{} "Whitelist entry updated"
// @Success 201 {object} map[string]interface{} "Whitelist entry created"
// @Failure 400 {object} map[string]interface{} "Invalid IP or parameters"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /whitelist [post]
// @Security BearerAuth
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

// NewRemoveFromWhitelistHandler godoc
// @Summary Remove IP from whitelist
// @Description Removes an IP address from the whitelist
// @Tags Whitelist
// @Accept json
// @Produce json
// @Param id path int true "Whitelist entry ID"
// @Success 200 {object} map[string]interface{} "IP removed from whitelist"
// @Failure 400 {object} map[string]interface{} "Invalid ID"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /whitelist/{id} [delete]
// @Security BearerAuth
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

// NewGetWhitelistForWAFHandler godoc
// @Summary Get whitelist for WAF
// @Description Returns whitelist for WAF (public endpoint, no auth required)
// @Tags Whitelist
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{} "Whitelist data"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /whitelist/waf [get]
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

		response := dto.NewStandardListResponse(whitelistMap, len(whitelistMap))
		c.JSON(200, response)
	}
}
