package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/service"
)

// NewGetAuditLogsHandler returns a handler to retrieve audit logs with pagination
func NewGetAuditLogsHandler(auditLogService *service.AuditLogService) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()

		// Get query parameters for filtering and pagination
		page := c.DefaultQuery("page", "1")
		pageSize := c.DefaultQuery("limit", "50")

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

		// Fetch paginated results using service
		auditLogs, total, err := auditLogService.GetPaginatedAuditLogs(ctx, pageNum, pageSizeNum)
		if err != nil {
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
func NewGetAuditLogStatsHandler(auditLogService *service.AuditLogService) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()

		// Get counts from service
		totalActions, _ := auditLogService.GetAuditLogsCount(ctx)
		successfulActions, _ := auditLogService.GetSuccessfulActionsCount(ctx)
		failedActions, _ := auditLogService.GetFailedActionsCount(ctx)

		// Get action breakdown
		actionBreakdown, err := auditLogService.GetActionBreakdown(ctx)
		if err != nil {
			actionBreakdown = make(map[string]int64)
		}

		c.JSON(http.StatusOK, gin.H{
			"total_actions":      totalActions,
			"successful_actions": successfulActions,
			"failed_actions":     failedActions,
			"action_breakdown":   actionBreakdown,
		})
	}
}
