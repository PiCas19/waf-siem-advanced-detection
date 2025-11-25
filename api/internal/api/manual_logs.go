package api

import (
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/logger"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/service"
)

// LogManualBlockRequest represents a manual block event to be logged to database only
// (This is for threat blocking via dashboard, not for IP blocklist)
type LogManualBlockRequest struct {
	IP          string `json:"ip" binding:"required"`
	ThreatType  string `json:"threat_type" binding:"required"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	URL         string `json:"url"`
	UserAgent   string `json:"user_agent"`
	Payload     string `json:"payload"`
}

// LogManualUnblockRequest represents a manual unblock event to be logged to database only
// (This is for threat unblocking via dashboard, not for IP blocklist)
type LogManualUnblockRequest struct {
	IP          string `json:"ip" binding:"required"`
	ThreatType  string `json:"threat_type" binding:"required"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	URL         string `json:"url"`
	UserAgent   string `json:"user_agent"`
	Payload     string `json:"payload"`
}

// NewLogManualBlockHandler handles logging of manual block events to database only
// This is for threat blocking via dashboard (creates custom rule), not for IP blocklist
func NewLogManualBlockHandler(logService *service.LogService, db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req LogManualBlockRequest
		if !ValidateJSON(c, &req) {
			return
		}

		// Save to database for persistence
		ctx := c.Request.Context()
		logEntry := &models.Log{
			ThreatType:    req.ThreatType,
			Severity:      req.Severity,
			Description:   req.Description,
			ClientIP:      req.IP,
			Method:        "MANUAL_BLOCK",
			URL:           req.URL,
			UserAgent:     req.UserAgent,
			Payload:       req.Payload,
			Blocked:       true,
			BlockedBy:     "manual",
			CreatedAt:     time.Now(),
		}

		if err := logService.CreateLog(ctx, logEntry); err != nil {
			logger.Log.WithError(err).Error("Failed to save manual block to database")
			InternalServerErrorWithCode(c, ErrDatabaseError, "Failed to log event")
			return
		}

		c.JSON(201, gin.H{"message": "Manual block logged successfully"})
	}
}

// NewLogManualUnblockHandler handles logging of manual unblock events to database only
// This is for threat unblocking via dashboard (deletes custom rule), not for IP blocklist
func NewLogManualUnblockHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req LogManualUnblockRequest
		if !ValidateJSON(c, &req) {
			return
		}

		// Note: Unblock is handled primarily by deleting the custom rule via /api/rules/{id}
		// This endpoint is kept for consistency but doesn't need to log anything special
		c.JSON(201, gin.H{"message": "Manual unblock processed successfully"})
	}
}

