package api

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/service"
)

// NewGetFalsePositivesHandler - Returns the list of false positives
func NewGetFalsePositivesHandler(falsePositiveService *service.FalsePositiveService) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()

		falsePositives, err := falsePositiveService.GetAllFalsePositives(ctx)
		if err != nil {
			c.JSON(500, gin.H{"error": "failed to fetch false positives"})
			return
		}

		c.JSON(200, gin.H{
			"false_positives": falsePositives,
			"count":           len(falsePositives),
		})
	}
}

// NewReportFalsePositiveHandler - Reports a threat as a false positive
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

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": "Invalid request"})
			return
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
			c.JSON(500, gin.H{"error": "failed to report false positive"})
			return
		}

		c.JSON(201, gin.H{
			"message": "False positive reported successfully",
			"entry":   falsePositive,
		})
	}
}

// NewUpdateFalsePositiveStatusHandler - Updates the status of a false positive
func NewUpdateFalsePositiveStatusHandler(falsePositiveService *service.FalsePositiveService) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		idUint, err := strconv.ParseUint(id, 10, 32)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid ID"})
			return
		}

		var req struct {
			Status       string `json:"status" binding:"required"`
			ReviewNotes  string `json:"review_notes"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": "Invalid request"})
			return
		}

		// Validate status
		if req.Status != "pending" && req.Status != "reviewed" && req.Status != "whitelisted" {
			c.JSON(400, gin.H{"error": "Invalid status"})
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
			c.JSON(500, gin.H{"error": "failed to update false positive"})
			return
		}

		c.JSON(200, gin.H{"message": "Status updated successfully"})
	}
}

// NewDeleteFalsePositiveHandler - Deletes a false positive
func NewDeleteFalsePositiveHandler(falsePositiveService *service.FalsePositiveService) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		idUint, err := strconv.ParseUint(id, 10, 32)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid ID"})
			return
		}

		ctx := c.Request.Context()

		if err := falsePositiveService.DeleteFalsePositive(ctx, uint(idUint)); err != nil {
			c.JSON(500, gin.H{"error": "failed to delete false positive"})
			return
		}

		c.JSON(200, gin.H{"message": "Entry deleted successfully"})
	}
}
