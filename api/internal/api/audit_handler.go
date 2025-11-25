package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/helpers"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/service"
)

// NewGetAuditLogsHandler godoc
// @Summary Get audit logs
// @Description Returns paginated list of audit logs
// @Tags Audit
// @Accept json
// @Produce json
// @Param limit query int false "Number of items per page (default 20, max 100)" default(20)
// @Param offset query int false "Pagination offset (default 0)" default(0)
// @Success 200 {object} map[string]interface{} "Audit logs with pagination"
// @Failure 400 {object} map[string]interface{} "Invalid parameters"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /audit-logs [get]
// @Security BearerAuth
func NewGetAuditLogsHandler(auditLogService *service.AuditLogService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Parse pagination parameters using standard helpers
		limit, offset, _, _, err := helpers.ParsePaginationParams(c)
		if err != nil {
			BadRequestWithCode(c, ErrInvalidRequest, err.Error())
			return
		}

		ctx := c.Request.Context()

		// Convert offset to page number (0-based to 1-based)
		// offset=0 -> page=1, offset=20 -> page=2, etc.
		page := (offset / limit) + 1

		// Fetch paginated results using service
		auditLogs, total, err := auditLogService.GetPaginatedAuditLogs(ctx, page, limit)
		if err != nil {
			InternalServerErrorWithCode(c, ErrServiceError, "Failed to fetch audit logs")
			return
		}

		// Build paginated response using standard format
		response := helpers.BuildStandardPaginatedResponse(auditLogs, limit, offset, total)

		c.JSON(http.StatusOK, gin.H{
			"audit_logs": response.Items,
			"pagination": response.Pagination,
		})
	}
}

// NewGetAuditLogStatsHandler godoc
// @Summary Get audit log statistics
// @Description Returns statistics about audit logs (total, successful, failed, breakdown)
// @Tags Audit
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{} "Audit log statistics"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /audit-logs/stats [get]
// @Security BearerAuth
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
