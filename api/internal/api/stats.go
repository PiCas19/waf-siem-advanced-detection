package api

import (
	"fmt"
	"sync"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/websocket"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type WAFStats struct {
	ThreatsDetected int                  `json:"threats_detected"`
	RequestsBlocked int                  `json:"requests_blocked"`
	TotalRequests   int                  `json:"total_requests"`
	LastSeen        string               `json:"last_seen"`
	Recent          []websocket.WAFEvent `json:"recent"`
}

var (
	statsMu sync.RWMutex
	stats   = WAFStats{
		Recent: make([]websocket.WAFEvent, 0, 5),
	}
)

func NewWAFEventHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var event websocket.WAFEvent
		if err := c.ShouldBindJSON(&event); err != nil {
			fmt.Printf("[ERROR] Failed to bind JSON: %v\n", err)
			fmt.Printf("[ERROR] Request body: %v\n", c.Request.Body)
			c.JSON(400, gin.H{"error": "invalid json"})
			return
		}

		fmt.Printf("[INFO] Received WAF event: IP=%s, Threat=%s, Method=%s, Path=%s\n", event.IP, event.Threat, event.Method, event.Path)

		event.Timestamp = time.Now().Format("2006-01-02T15:04:05Z07:00")

		statsMu.Lock()
		stats.ThreatsDetected++
		if event.Blocked {
			stats.RequestsBlocked++
		}
		stats.TotalRequests++
		stats.LastSeen = time.Now().Format("15:04:05")

		fmt.Printf("[INFO] Stats updated: Threats=%d, Blocked=%d, Total=%d (Blocked=%v)\n", stats.ThreatsDetected, stats.RequestsBlocked, stats.TotalRequests, event.Blocked)

		if len(stats.Recent) >= 5 {
			stats.Recent = stats.Recent[1:]
		}
		stats.Recent = append(stats.Recent, event)
		statsMu.Unlock()

		// Save event to database
		log := models.Log{
			ThreatType:  event.Threat,
			ClientIP:    event.IP,
			Method:      event.Method,
			URL:         event.Path,
			UserAgent:   event.UA,
			CreatedAt:   time.Now(),
			Blocked:     event.Blocked,
		}
		if err := db.Create(&log).Error; err != nil {
			fmt.Printf("[ERROR] Failed to save log to database: %v\n", err)
		}

		websocket.Broadcast(event)

		c.JSON(200, gin.H{"status": "event_received"})
	}
}

func WAFStatsHandler(c *gin.Context) {
	statsMu.RLock()
	defer statsMu.RUnlock()
	c.JSON(200, stats)
}