package api

import (
	"fmt"
	"sync"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/geoip"
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

// Iniezione della dipendenza del database
var statsDB *gorm.DB

// SetStatsDB imposta il database per il gestore delle statistiche
func SetStatsDB(db *gorm.DB) {
	statsDB = db
}

func WAFStatsHandler(c *gin.Context) {
	// Se il database è disponibile, carica i dati dal database invece che dalla memoria
	if statsDB != nil {
		var totalLogs int64
		var blockedLogs int64
		var threatLogs int64

		// Conta tutti i logs
		statsDB.Model(&models.Log{}).Count(&totalLogs)

		// Conta i logs bloccati
		statsDB.Model(&models.Log{}).Where("blocked = ?", true).Count(&blockedLogs)

		// Conta i logs con minacce (tutti sono considerati minacce)
		statsDB.Model(&models.Log{}).Count(&threatLogs)

		// Carica i log recenti
		var recentLogs []models.Log
		statsDB.Order("created_at DESC").Limit(5).Find(&recentLogs)

		// Converti i log recenti a WAFEvent
		recentEvents := make([]websocket.WAFEvent, 0, len(recentLogs))
		for _, log := range recentLogs {
			recentEvents = append(recentEvents, websocket.WAFEvent{
				IP:        log.ClientIP,
				Threat:    log.ThreatType,
				Blocked:   log.Blocked,
				Timestamp: log.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
				Method:    log.Method,
				Path:      log.URL,
				UA:        log.UserAgent,
			})
		}

		c.JSON(200, WAFStats{
			ThreatsDetected: int(threatLogs),
			RequestsBlocked: int(blockedLogs),
			TotalRequests:   int(totalLogs),
			LastSeen:        fmt.Sprintf("%d minuti fa", 0),
			Recent:          recentEvents,
		})
		return
	}

	// Fallback: usa i dati in memoria se il database non è disponibile
	statsMu.RLock()
	defer statsMu.RUnlock()
	c.JSON(200, stats)
}

// GeolocationData represents geolocation statistics
type GeolocationData struct {
	Country string `json:"country"`
	Count   int    `json:"count"`
}

// GetGeolocationHandler returns geolocation distribution of threats
func GetGeolocationHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		geoService, err := geoip.GetInstance()
		if err != nil {
			fmt.Printf("[ERROR] Failed to initialize GeoIP service: %v\n", err)
			c.JSON(500, gin.H{"error": "geoip service unavailable"})
			return
		}

		var logs []models.Log
		result := db.Find(&logs)
		if result.Error != nil {
			fmt.Printf("[ERROR] Failed to fetch logs: %v\n", result.Error)
			c.JSON(500, gin.H{"error": "database error"})
			return
		}

		// Group logs by country
		countryMap := make(map[string]int)
		for _, log := range logs {
			country := geoService.LookupCountry(log.ClientIP)
			countryMap[country]++
		}

		// Convert to response format
		var response []GeolocationData
		for country, count := range countryMap {
			response = append(response, GeolocationData{
				Country: country,
				Count:   count,
			})
		}

		c.JSON(200, gin.H{
			"data": response,
		})
	}
}