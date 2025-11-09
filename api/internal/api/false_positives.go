package api

import (
	"fmt"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"gorm.io/gorm"
)

// GetFalsePositives - Ritorna la lista dei false positives
func NewGetFalsePositivesHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var falsePositives []models.FalsePositive
		if err := db.Order("created_at DESC").Find(&falsePositives).Error; err != nil {
			c.JSON(500, gin.H{"error": "failed to fetch false positives"})
			return
		}
		c.JSON(200, gin.H{
			"false_positives": falsePositives,
			"count":           len(falsePositives),
		})
	}
}

// ReportFalsePositive - Segnala una minaccia come falso positivo
func NewReportFalsePositiveHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			ThreatType string `json:"threat_type" binding:"required"`
			ClientIP   string `json:"client_ip" binding:"required"`
			Method     string `json:"method"`
			URL        string `json:"url"`
			Payload    string `json:"payload"`
			UserAgent  string `json:"user_agent"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": "Invalid request"})
			return
		}

		falsePositive := models.FalsePositive{
			ThreatType: req.ThreatType,
			ClientIP:   req.ClientIP,
			Method:     req.Method,
			URL:        req.URL,
			Payload:    req.Payload,
			UserAgent:  req.UserAgent,
			Status:     "pending",
		}

		if err := db.Create(&falsePositive).Error; err != nil {
				c.JSON(500, gin.H{"error": "failed to report false positive"})
			return
		}

		// Log to audit logs using the LogFalsePositiveAction helper
		userID := uint(0)
		userEmail := "system"
		if user, exists := c.Get("user"); exists {
			if userModel, ok := user.(*models.User); ok {
				userID = userModel.ID
				userEmail = userModel.Email
			}
		}

		ipAddress := c.ClientIP()
		LogFalsePositiveAction(db, userID, userEmail, "REPORT", fmt.Sprintf("%d", falsePositive.ID), req.ThreatType, req.ClientIP, "pending", ipAddress)

		c.JSON(201, gin.H{
			"message": "False positive reported successfully",
			"entry":   falsePositive,
		})
	}
}

// UpdateFalsePositiveStatus - Aggiorna lo stato di un false positive
func NewUpdateFalsePositiveStatusHandler(db *gorm.DB) gin.HandlerFunc {
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

		// Valida lo status
		if req.Status != "pending" && req.Status != "reviewed" && req.Status != "whitelisted" {
			c.JSON(400, gin.H{"error": "Invalid status"})
			return
		}

		now := time.Now()
		update := map[string]interface{}{
			"status":       req.Status,
			"review_notes": req.ReviewNotes,
			"reviewed_at":  &now,
		}

		if err := db.Model(&models.FalsePositive{}).Where("id = ?", uint(idUint)).Updates(update).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				c.JSON(404, gin.H{"error": "Entry not found"})
			} else {
					c.JSON(500, gin.H{"error": "failed to update false positive"})
			}
			return
		}

		// Se è whitelisted, aggiungi automaticamente l'IP alla whitelist
		if req.Status == "whitelisted" {
			var fp models.FalsePositive
			db.First(&fp, uint(idUint))

			whitelist := models.WhitelistedIP{
				IPAddress: fp.ClientIP,
				Reason:    "Auto-whitelisted from false positive: " + fp.ThreatType,
			}
			db.Create(&whitelist)
		}

	
		c.JSON(200, gin.H{"message": "Status updated successfully"})
	}
}

// DeleteFalsePositive - Elimina un false positive
func NewDeleteFalsePositiveHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		idUint, err := strconv.ParseUint(id, 10, 32)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid ID"})
			return
		}

		if err := db.Delete(&models.FalsePositive{}, uint(idUint)).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				c.JSON(404, gin.H{"error": "Entry not found"})
			} else {
					c.JSON(500, gin.H{"error": "failed to delete false positive"})
			}
			return
		}


		c.JSON(200, gin.H{"message": "Entry deleted successfully"})
	}
}
