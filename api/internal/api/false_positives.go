package api

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/helpers"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/service"
)

// NewGetFalsePositivesHandler godoc
// @Summary Get false positives list
// @Description Returns paginated list of reported false positives
// @Tags FalsePositives
// @Accept json
// @Produce json
// @Param limit query int false "Number of items per page (default 20, max 100)" default(20)
// @Param offset query int false "Pagination offset (default 0)" default(0)
// @Success 200 {object} map[string]interface{} "False positives with pagination"
// @Failure 400 {object} map[string]interface{} "Invalid parameters"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /false-positives [get]
// @Security BearerAuth
func NewGetFalsePositivesHandler(falsePositiveService *service.FalsePositiveService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Parse pagination parameters
		limit, offset, _, _, err := helpers.ParsePaginationParams(c)
		if err != nil {
			BadRequestWithCode(c, ErrInvalidRequest, err.Error())
			return
		}

		ctx := c.Request.Context()

		// Fetch paginated false positives
		falsePositives, total, err := falsePositiveService.GetFalsePositivesPaginated(ctx, offset, limit)
		if err != nil {
			InternalServerErrorWithCode(c, ErrServiceError, "Failed to fetch false positives")
			return
		}

		// Build paginated response
		response := helpers.BuildStandardPaginatedResponse(falsePositives, limit, offset, total)

		c.JSON(200, gin.H{
			"false_positives": response.Items,
			"pagination":      response.Pagination,
			"count":           len(response.Items.([]models.FalsePositive)),
		})
	}
}

// NewReportFalsePositiveHandler godoc
// @Summary Report false positive
// @Description Reports a threat as a false positive
// @Tags FalsePositives
// @Accept json
// @Produce json
// @Param request body object{threat_type=string,description=string,client_ip=string,method=string,url=string,payload=string,user_agent=string} true "False positive report"
// @Success 201 {object} map[string]interface{} "False positive reported successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /false-positives [post]
// @Security BearerAuth
func NewReportFalsePositiveHandler(falsePositiveService *service.FalsePositiveService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			ThreatType  string `json:"threat_type" binding:"required"`
			Description string `json:"description"`
			ClientIP    string `json:"client_ip" binding:"required"`
			Method      string `json:"method"`
			URL         string `json:"url"`
			Payload     string `json:"payload"`
			UserAgent   string `json:"user_agent"`
		}

		if !ValidateJSON(c, &req) {
			return
		}

		// Validate threat type
		if err := helpers.ValidateNonEmpty(req.ThreatType, "Threat type"); err != nil {
			BadRequestWithCode(c, ErrInvalidRequest, err.Error())
			return
		}

		// Validate client IP
		if err := helpers.ValidateIPAddress(req.ClientIP); err != nil {
			BadRequestWithCode(c, ErrInvalidIP, "Invalid client IP: "+err.Error())
			return
		}

		// Validate URL if provided
		if req.URL != "" {
			if err := helpers.ValidateURL(req.URL); err != nil {
				BadRequestWithCode(c, ErrInvalidRequest, "Invalid URL: "+err.Error())
				return
			}
		}

		// Validate HTTP method if provided
		if req.Method != "" {
			if err := helpers.ValidateHTTPMethod(req.Method); err != nil {
				BadRequestWithCode(c, ErrInvalidRequest, err.Error())
				return
			}
		}

		// Validate payload if provided
		if req.Payload != "" {
			if err := helpers.ValidatePayload(req.Payload); err != nil {
				BadRequestWithCode(c, ErrInvalidRequest, err.Error())
				return
			}
		}

		// Validate user agent if provided
		if req.UserAgent != "" {
			if err := helpers.ValidateUserAgent(req.UserAgent); err != nil {
				BadRequestWithCode(c, ErrInvalidRequest, err.Error())
				return
			}
		}

		ctx := c.Request.Context()

		falsePositive := models.FalsePositive{
			ThreatType:  req.ThreatType,
			Description: req.Description,
			ClientIP:    req.ClientIP,
			Method:      req.Method,
			URL:         req.URL,
			Payload:     req.Payload,
			UserAgent:   req.UserAgent,
			Status:      "pending",
		}

		if err := falsePositiveService.ReportFalsePositive(ctx, &falsePositive); err != nil {
			InternalServerErrorWithCode(c, ErrDatabaseError, "Failed to report false positive")
			return
		}

		c.JSON(201, gin.H{
			"message": "False positive reported successfully",
			"entry":   falsePositive,
		})
	}
}

// NewUpdateFalsePositiveStatusHandler godoc
// @Summary Update false positive status
// @Description Updates the status and review notes of a false positive
// @Tags FalsePositives
// @Accept json
// @Produce json
// @Param id path int true "False positive ID"
// @Param request body object{status=string,review_notes=string} true "Status update"
// @Success 200 {object} map[string]interface{} "Status updated successfully"
// @Failure 400 {object} map[string]interface{} "Invalid ID or status"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /false-positives/{id} [put]
// @Security BearerAuth
func NewUpdateFalsePositiveStatusHandler(falsePositiveService *service.FalsePositiveService) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		idUint, err := strconv.ParseUint(id, 10, 32)
		if err != nil {
			BadRequestWithCode(c, ErrInvalidRequest, "Invalid ID")
			return
		}

		var req struct {
			Status       string `json:"status" binding:"required"`
			ReviewNotes  string `json:"review_notes"`
		}

		if !ValidateJSON(c, &req) {
			return
		}

		// Validate status
		if err := helpers.ValidateFalsePositiveStatus(req.Status); err != nil {
			BadRequestWithCode(c, ErrInvalidRequest, err.Error())
			return
		}

		// Validate review notes if provided
		if err := helpers.ValidateReviewNotes(req.ReviewNotes); err != nil {
			BadRequestWithCode(c, ErrInvalidRequest, err.Error())
			return
		}

		ctx := c.Request.Context()

		update := models.FalsePositive{
			ID:          uint(idUint),
			Status:      req.Status,
			ReviewNotes: req.ReviewNotes,
		}
		now := time.Now()
		update.ReviewedAt = &now

		if err := falsePositiveService.UpdateFalsePositive(ctx, &update); err != nil {
			InternalServerErrorWithCode(c, ErrDatabaseError, "Failed to update false positive")
			return
		}

		c.JSON(200, gin.H{"message": "Status updated successfully"})
	}
}

// NewDeleteFalsePositiveHandler godoc
// @Summary Delete false positive
// @Description Deletes a false positive entry
// @Tags FalsePositives
// @Accept json
// @Produce json
// @Param id path int true "False positive ID"
// @Success 200 {object} map[string]interface{} "Entry deleted successfully"
// @Failure 400 {object} map[string]interface{} "Invalid ID"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /false-positives/{id} [delete]
// @Security BearerAuth
func NewDeleteFalsePositiveHandler(falsePositiveService *service.FalsePositiveService) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		idUint, err := strconv.ParseUint(id, 10, 32)
		if err != nil {
			BadRequestWithCode(c, ErrInvalidRequest, "Invalid ID")
			return
		}

		ctx := c.Request.Context()

		if err := falsePositiveService.DeleteFalsePositive(ctx, uint(idUint)); err != nil {
			InternalServerErrorWithCode(c, ErrDatabaseError, "Failed to delete false positive")
			return
		}

		c.JSON(200, gin.H{"message": "Entry deleted successfully"})
	}
}
