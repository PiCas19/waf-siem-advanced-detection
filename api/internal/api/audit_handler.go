package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
)

// NewGetAuditLogsHandler returns a handler to retrieve audit logs
func NewGetAuditLogsHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get query parameters for filtering and pagination
		page := c.DefaultQuery("page", "1")
		pageSize := c.DefaultQuery("limit", "50")
		action := c.Query("action")     // Filter by action
		category := c.Query("category") // Filter by category
		userID := c.Query("user_id")    // Filter by user
		status := c.Query("status")     // Filter by status (success, failure)

		// Parse pagination
		pageNum, err := strconv.Atoi(page)
		if err != nil || pageNum < 1 {
			pageNum = 1
		}
		pageSizeNum, err := strconv.Atoi(pageSize)
		if err != nil || pageSizeNum < 1 {
			pageSizeNum = 50
		}
		if pageSizeNum > 500 {
			pageSizeNum = 500 // Max limit
		}

		// Build query
		query := db.Order("created_at DESC")

		// Apply filters
		if action != "" {
			query = query.Where("action = ?", action)
		}
		if category != "" {
			query = query.Where("category = ?", category)
		}
		if userID != "" {
			query = query.Where("user_id = ?", userID)
		}
		if status != "" {
			query = query.Where("status = ?", status)
		}

		// Count total for pagination
		var total int64
		if err := query.Model(&models.AuditLog{}).Count(&total).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count audit logs"})
			return
		}

		// Fetch paginated results
		var auditLogs []models.AuditLog
		offset := (pageNum - 1) * pageSizeNum
		if err := query.Offset(offset).Limit(pageSizeNum).Find(&auditLogs).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch audit logs"})
			return
		}

		// Calculate total pages
		totalPages := (int(total) + pageSizeNum - 1) / pageSizeNum

		c.JSON(http.StatusOK, gin.H{
			"audit_logs": auditLogs,
			"pagination": gin.H{
				"page":        pageNum,
				"limit":       pageSizeNum,
				"total":       total,
				"total_pages": totalPages,
			},
		})
	}
}

// NewGetAuditLogStatsHandler returns statistics about audit logs
func NewGetAuditLogStatsHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var (
			totalActions      int64
			successfulActions int64
			failedActions     int64
		)

		// Count total actions
		db.Model(&models.AuditLog{}).Count(&totalActions)

		// Count successful actions
		db.Model(&models.AuditLog{}).Where("status = ?", "success").Count(&successfulActions)

		// Count failed actions
		db.Model(&models.AuditLog{}).Where("status = ?", "failure").Count(&failedActions)

		// Get action breakdown
		var actionCounts []struct {
			Action string
			Count  int64
		}
		db.Model(&models.AuditLog{}).
			Select("action, COUNT(*) as count").
			Group("action").
			Order("count DESC").
			Limit(10).
			Scan(&actionCounts)

		// Get user activity breakdown
		var userCounts []struct {
			UserEmail string
			Count     int64
		}
		db.Model(&models.AuditLog{}).
			Select("user_email, COUNT(*) as count").
			Group("user_email").
			Order("count DESC").
			Limit(10).
			Scan(&userCounts)

		c.JSON(http.StatusOK, gin.H{
			"total_actions":      totalActions,
			"successful_actions": successfulActions,
			"failed_actions":     failedActions,
			"action_breakdown":   actionCounts,
			"user_activity":      userCounts,
		})
	}
}
