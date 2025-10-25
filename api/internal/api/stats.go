package api

import (
	"fmt"
	"sync"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/websocket"
	"github.com/gin-gonic/gin"
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

func WAFEventHandler(c *gin.Context) {
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
	stats.RequestsBlocked++
	stats.TotalRequests++
	stats.LastSeen = time.Now().Format("15:04:05")

	fmt.Printf("[INFO] Stats updated: Threats=%d, Blocked=%d, Total=%d\n", stats.ThreatsDetected, stats.RequestsBlocked, stats.TotalRequests)

	if len(stats.Recent) >= 5 {
		stats.Recent = stats.Recent[1:]
	}
	stats.Recent = append(stats.Recent, event)
	statsMu.Unlock()

	websocket.Broadcast(event)

	c.JSON(200, gin.H{"status": "event_received"})
}

func WAFStatsHandler(c *gin.Context) {
	statsMu.RLock()
	defer statsMu.RUnlock()
	c.JSON(200, stats)
}