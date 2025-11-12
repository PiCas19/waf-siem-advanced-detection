package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/api"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/test/helpers"
)

func TestNewWAFEventHandler(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	router := gin.New()
	router.POST("/waf/event", api.NewWAFEventHandler(db))

	t.Run("successful event handler with blocked event", func(t *testing.T) {
		eventJSON := `{
			"ip": "192.168.1.1",
			"threat": "XSS",
			"description": "XSS Attack",
			"method": "GET",
			"path": "/test?id=<script>",
			"ua": "Mozilla/5.0",
			"payload": "<script>alert(1)</script>",
			"blocked": true,
			"blocked_by": "auto"
		}`

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/waf/event", bytes.NewBufferString(eventJSON))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]string
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "event_received", response["status"])

		var log models.Log
		result := db.Where("client_ip = ?", "192.168.1.1").First(&log)
		assert.NoError(t, result.Error)
		assert.Equal(t, "XSS", log.ThreatType)
		assert.Equal(t, "192.168.1.1", log.ClientIP)
		assert.Equal(t, "GET", log.Method)
		assert.Equal(t, "/test?id=<script>", log.URL)
		assert.True(t, log.Blocked)
		assert.Equal(t, "auto", log.BlockedBy)
		assert.Equal(t, "High", log.Severity)
	})

	t.Run("successful event handler with unblocked event", func(t *testing.T) {
		eventJSON := `{
			"ip": "10.0.0.1",
			"threat": "CUSTOM_RULE",
			"description": "Custom detection",
			"method": "POST",
			"path": "/api/data",
			"ua": "curl/7.68.0",
			"payload": "",
			"blocked": false,
			"blocked_by": ""
		}`

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/waf/event", bytes.NewBufferString(eventJSON))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var log models.Log
		db.Where("client_ip = ?", "10.0.0.1").First(&log)
		assert.False(t, log.Blocked)
		assert.Equal(t, "Medium", log.Severity)
	})

	t.Run("event handler with critical threat", func(t *testing.T) {
		eventJSON := `{
			"ip": "192.168.1.2",
			"threat": "SQL_INJECTION",
			"description": "SQL Injection Attempt",
			"method": "GET",
			"path": "/search?q=' OR '1'='1",
			"blocked": true,
			"blocked_by": "auto"
		}`

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/waf/event", bytes.NewBufferString(eventJSON))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		var log models.Log
		db.Where("client_ip = ?", "192.168.1.2").First(&log)
		assert.Equal(t, "Critical", log.Severity)
	})

	t.Run("event handler with invalid JSON", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/waf/event", bytes.NewBufferString("invalid json"))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]string
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "invalid json", response["error"])
	})

	t.Run("event handler with empty payload", func(t *testing.T) {
		eventJSON := `{
			"ip": "192.168.1.3",
			"threat": "LFI",
			"method": "GET",
			"path": "/file?name=../etc/passwd",
			"blocked": true
		}`

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/waf/event", bytes.NewBufferString(eventJSON))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var log models.Log
		db.Where("client_ip = ?", "192.168.1.3").First(&log)
		assert.Equal(t, "LFI", log.ThreatType)
		assert.Equal(t, "High", log.Severity)
	})
}

func TestSetStatsDB(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	t.Run("set stats database", func(t *testing.T) {
		api.SetStatsDB(db)

		log := models.Log{
			ThreatType: "XSS",
			ClientIP:   "192.168.1.1",
			Blocked:    true,
			Method:     "GET",
			URL:        "/test",
		}
		db.Create(&log)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		api.WAFStatsHandler(c)

		assert.Equal(t, http.StatusOK, w.Code)

		var stats api.WAFStats
		json.Unmarshal(w.Body.Bytes(), &stats)
		assert.Equal(t, 1, stats.ThreatsDetected)
		assert.Equal(t, 1, stats.RequestsBlocked)
		assert.Equal(t, 1, stats.TotalRequests)
	})
}

func TestWAFStatsHandler(t *testing.T) {
	t.Run("waf stats handler with database", func(t *testing.T) {
		db := helpers.SetupTestDB(t)
		defer helpers.CleanupTestDB(t, db)
		api.SetStatsDB(db)

		logs := []models.Log{
			{
				ThreatType: "XSS",
				ClientIP:   "192.168.1.1",
				Method:     "GET",
				URL:        "/test",
				Blocked:    true,
				BlockedBy:  "auto",
			},
			{
				ThreatType: "SQL_INJECTION",
				ClientIP:   "192.168.1.2",
				Method:     "POST",
				URL:        "/api",
				Blocked:    true,
				BlockedBy:  "manual",
			},
			{
				ThreatType: "CUSTOM_RULE",
				ClientIP:   "192.168.1.3",
				Method:     "GET",
				URL:        "/admin",
				Blocked:    false,
				BlockedBy:  "",
			},
		}

		for _, log := range logs {
			db.Create(&log)
		}

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		api.WAFStatsHandler(c)

		assert.Equal(t, http.StatusOK, w.Code)

		var stats api.WAFStats
		json.Unmarshal(w.Body.Bytes(), &stats)
		assert.Equal(t, 3, stats.ThreatsDetected)
		assert.Equal(t, 2, stats.RequestsBlocked)
		assert.Equal(t, 3, stats.TotalRequests)
	})

	t.Run("waf stats handler empty database", func(t *testing.T) {
		db := helpers.SetupTestDB(t)
		defer helpers.CleanupTestDB(t, db)
		api.SetStatsDB(db)

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		api.WAFStatsHandler(c)

		assert.Equal(t, http.StatusOK, w.Code)

		var stats api.WAFStats
		json.Unmarshal(w.Body.Bytes(), &stats)
		assert.Equal(t, 0, stats.ThreatsDetected)
		assert.Equal(t, 0, stats.RequestsBlocked)
		assert.Equal(t, 0, stats.TotalRequests)
	})

	t.Run("waf stats handler filters blocked", func(t *testing.T) {
		db := helpers.SetupTestDB(t)
		defer helpers.CleanupTestDB(t, db)
		api.SetStatsDB(db)

		for i := 0; i < 3; i++ {
			log := models.Log{
				ThreatType: "XSS",
				ClientIP:   "192.168.1.1",
				Method:     "GET",
				URL:        "/test",
				Blocked:    true,
			}
			db.Create(&log)
		}

		for i := 0; i < 2; i++ {
			log := models.Log{
				ThreatType: "CUSTOM",
				ClientIP:   "192.168.1.2",
				Method:     "GET",
				URL:        "/test",
				Blocked:    false,
			}
			db.Create(&log)
		}

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		api.WAFStatsHandler(c)

		var stats api.WAFStats
		json.Unmarshal(w.Body.Bytes(), &stats)
		assert.Equal(t, 5, stats.TotalRequests)
		assert.Equal(t, 3, stats.RequestsBlocked)
		assert.Equal(t, 5, stats.ThreatsDetected)
	})

	t.Run("waf stats handler recent events", func(t *testing.T) {
		db := helpers.SetupTestDB(t)
		defer helpers.CleanupTestDB(t, db)
		api.SetStatsDB(db)

		for i := 1; i <= 10; i++ {
			log := models.Log{
				ThreatType: "XSS",
				ClientIP:   "192.168.1.1",
				Method:     "GET",
				URL:        "/test",
				Blocked:    true,
				BlockedBy:  "auto",
				UserAgent:  "Mozilla/5.0",
				Payload:    "<script>",
			}
			db.Create(&log)
		}

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		api.WAFStatsHandler(c)

		var stats api.WAFStats
		json.Unmarshal(w.Body.Bytes(), &stats)

		assert.Equal(t, 5, len(stats.Recent))
		assert.Equal(t, 10, stats.TotalRequests)
	})
}
