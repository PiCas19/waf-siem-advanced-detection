package api

import (
	"github.com/gin-gonic/gin"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"gorm.io/gorm"
)

func NewGetLogsHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var logs []models.Log
		if err := db.Order("created_at DESC").Find(&logs).Error; err != nil {
			c.JSON(500, gin.H{"error": "failed to fetch logs"})
			return
		}
		c.JSON(200, gin.H{"logs": logs})
	}
}