package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/api"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/test/helpers"
)

func TestGetBlocklist(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	// Create test data
	now := time.Now()
	futureTime := now.Add(24 * time.Hour)
	pastTime := now.Add(-24 * time.Hour)

	blockedIPs := []models.BlockedIP{
		{
			IPAddress:   "192.168.1.100",
			Description: "XSS",
			Reason:      "Malicious XSS attempt",
			Permanent:   true,
		},
		{
			IPAddress:   "192.168.1.101",
			Description: "SQL_INJECTION",
			Reason:      "SQL injection detected",
			Permanent:   false,
			ExpiresAt:   &futureTime,
		},
		{
			IPAddress:   "192.168.1.102",
			Description: "LFI",
			Reason:      "Path traversal attempt",
			Permanent:   false,
			ExpiresAt:   &pastTime, // Expired
		},
	}

	for _, ip := range blockedIPs {
		assert.NoError(t, db.Create(&ip).Error)
	}

	router := gin.New()
	router.GET("/blocklist", api.GetBlocklist(db))

	t.Run("get blocklist success - returns only active blocks", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/blocklist", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response struct {
			BlockedIPs []models.BlockedIP `json:"blocked_ips"`
			Count      int                `json:"count"`
		}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, 2, response.Count)
		assert.Equal(t, 2, len(response.BlockedIPs))
	})

	t.Run("get blocklist empty database", func(t *testing.T) {
		// Clear the database
		db.Exec("DELETE FROM blocked_ips")

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/blocklist", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response struct {
			BlockedIPs []models.BlockedIP `json:"blocked_ips"`
			Count      int                `json:"count"`
		}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, 0, response.Count)
	})
}

func TestNewBlockIPHandler(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	router := gin.New()
	router.POST("/block", api.NewBlockIPHandler(db))

	t.Run("factory function creates handler successfully", func(t *testing.T) {
		handler := api.NewBlockIPHandler(db)
		assert.NotNil(t, handler)
	})
}

func TestNewUnblockIPHandler(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	router := gin.New()
	router.DELETE("/unblock/:ip", api.NewUnblockIPHandler(db))

	t.Run("factory function creates handler successfully", func(t *testing.T) {
		handler := api.NewUnblockIPHandler(db)
		assert.NotNil(t, handler)
	})
}

func TestBlockIPWithDB(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(1))
		c.Set("user_email", "test@example.com")
		c.Next()
	})
	router.POST("/block", api.NewBlockIPHandler(db))

	t.Run("block IP successfully - permanent with duration -1", func(t *testing.T) {
		payload := map[string]interface{}{
			"ip":             "192.168.1.100",
			"threat":         "XSS",
			"reason":         "Malicious XSS attempt detected",
			"permanent":      false,
			"duration_hours": -1,
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/block", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusCreated {
			t.Logf("Response body: %s", w.Body.String())
		}
		assert.Equal(t, http.StatusCreated, w.Code)

		var response struct {
			Message string            `json:"message"`
			Entry   models.BlockedIP  `json:"entry"`
		}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, "IP blocked successfully", response.Message)
		assert.Equal(t, "192.168.1.100", response.Entry.IPAddress)
		assert.Equal(t, "XSS", response.Entry.Description)
		assert.True(t, response.Entry.Permanent)
	})

	t.Run("block IP successfully - temporary with duration", func(t *testing.T) {
		payload := map[string]interface{}{
			"ip":             "192.168.1.101",
			"threat":         "SQL_INJECTION",
			"reason":         "SQL injection attempt",
			"permanent":      false,
			"duration_hours": 48,
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/block", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var response struct {
			Entry models.BlockedIP `json:"entry"`
		}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.False(t, response.Entry.Permanent)
		assert.NotNil(t, response.Entry.ExpiresAt)
	})

	t.Run("block IP successfully - temporary with 24 hour duration", func(t *testing.T) {
		payload := map[string]interface{}{
			"ip":             "192.168.1.102",
			"threat":         "LFI",
			"reason":         "Local file inclusion",
			"permanent":      false,
			"duration_hours": 24,
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/block", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var response struct {
			Entry models.BlockedIP `json:"entry"`
		}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.False(t, response.Entry.Permanent)
		assert.NotNil(t, response.Entry.ExpiresAt)
	})

	t.Run("block IP successfully - temporary with 1 hour duration", func(t *testing.T) {
		payload := map[string]interface{}{
			"ip":             "192.168.1.103",
			"threat":         "COMMAND_INJECTION",
			"reason":         "Command injection detected",
			"permanent":      false,
			"duration_hours": 1,
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/block", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var response struct{
			Entry models.BlockedIP `json:"entry"`
		}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.False(t, response.Entry.Permanent)
		assert.NotNil(t, response.Entry.ExpiresAt)
	})

	t.Run("update existing block - same IP and threat", func(t *testing.T) {
		// First block
		payload := map[string]interface{}{
			"ip":             "192.168.1.200",
			"threat":         "XSS",
			"reason":         "Initial block",
			"permanent":      false,
			"duration_hours": 48,
		}
		body, _ := json.Marshal(payload)
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/block", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusCreated, w.Code)

		// Update with same IP and threat
		payload2 := map[string]interface{}{
			"ip":             "192.168.1.200",
			"threat":         "XSS",
			"reason":         "Updated reason",
			"permanent":      false,
			"duration_hours": -1,
		}
		body2, _ := json.Marshal(payload2)
		w2 := httptest.NewRecorder()
		req2, _ := http.NewRequest("POST", "/block", bytes.NewBuffer(body2))
		req2.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w2, req2)

		assert.Equal(t, http.StatusOK, w2.Code)

		var response struct {
			Message string           `json:"message"`
			Entry   models.BlockedIP `json:"entry"`
		}
		json.Unmarshal(w2.Body.Bytes(), &response)
		assert.Equal(t, "IP block updated successfully", response.Message)
		assert.True(t, response.Entry.Permanent)
		assert.Equal(t, "Updated reason", response.Entry.Reason)
	})

	t.Run("block IP - invalid JSON", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/block", bytes.NewBuffer([]byte("invalid json")))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "Invalid request", response["error"])
	})

	t.Run("block IP - missing required field ip", func(t *testing.T) {
		payload := map[string]interface{}{
			"threat": "XSS",
			"reason": "Test reason",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/block", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("block IP - missing required field threat", func(t *testing.T) {
		payload := map[string]interface{}{
			"ip":     "192.168.1.100",
			"reason": "Test reason",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/block", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("block IP - missing required field reason", func(t *testing.T) {
		payload := map[string]interface{}{
			"ip":     "192.168.1.100",
			"threat": "XSS",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/block", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("block IP - invalid IP address", func(t *testing.T) {
		payload := map[string]interface{}{
			"ip":     "invalid.ip.address",
			"threat": "XSS",
			"reason": "Test reason",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/block", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Contains(t, response["error"], "invalid IP address")
	})

	t.Run("block IP - empty IP address", func(t *testing.T) {
		payload := map[string]interface{}{
			"ip":     "",
			"threat": "XSS",
			"reason": "Test reason",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/block", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("block IP - loopback IP address", func(t *testing.T) {
		payload := map[string]interface{}{
			"ip":     "127.0.0.1",
			"threat": "XSS",
			"reason": "Test reason",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/block", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Contains(t, response["error"], "loopback")
	})

	t.Run("block IP - invalid threat type", func(t *testing.T) {
		payload := map[string]interface{}{
			"ip":     "192.168.1.100",
			"threat": "INVALID@THREAT!",
			"reason": "Test reason",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/block", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Contains(t, response["error"], "threat type")
	})

	t.Run("block IP - empty threat type", func(t *testing.T) {
		payload := map[string]interface{}{
			"ip":     "192.168.1.100",
			"threat": "",
			"reason": "Test reason",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/block", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("block IP - threat type too long", func(t *testing.T) {
		longThreat := string(make([]byte, 300))
		payload := map[string]interface{}{
			"ip":     "192.168.1.100",
			"threat": longThreat,
			"reason": "Test reason",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/block", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("block IP - invalid reason", func(t *testing.T) {
		payload := map[string]interface{}{
			"ip":     "192.168.1.100",
			"threat": "XSS",
			"reason": "Invalid@#$%^&*()+={}[]|\\<>?~`",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/block", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Contains(t, response["error"], "reason")
	})

	t.Run("block IP - empty reason", func(t *testing.T) {
		payload := map[string]interface{}{
			"ip":     "192.168.1.100",
			"threat": "XSS",
			"reason": "",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/block", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("block IP - reason too long", func(t *testing.T) {
		longReason := string(make([]byte, 600))
		payload := map[string]interface{}{
			"ip":     "192.168.1.100",
			"threat": "XSS",
			"reason": longReason,
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/block", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("block IP - invalid duration (zero) should fail", func(t *testing.T) {
		payload := map[string]interface{}{
			"ip":             "192.168.1.100",
			"threat":         "XSS",
			"reason":         "Test reason",
			"duration_hours": 0,
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/block", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Contains(t, response["error"], "duration")
	})

	t.Run("block IP - invalid duration (negative, not -1)", func(t *testing.T) {
		payload := map[string]interface{}{
			"ip":             "192.168.1.100",
			"threat":         "XSS",
			"reason":         "Test reason",
			"duration_hours": -5,
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/block", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("block IP - invalid duration (exceeds max)", func(t *testing.T) {
		payload := map[string]interface{}{
			"ip":             "192.168.1.100",
			"threat":         "XSS",
			"reason":         "Test reason",
			"duration_hours": 100000,
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/block", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("block IP - updates logs for blocked IP", func(t *testing.T) {
		// Create a log entry first
		log := models.Log{
			ThreatType:  "XSS",
			Description: "XSS",
			ClientIP:    "192.168.1.150",
			Severity:    "high",
			Method:      "GET",
			URL:         "/test",
			Blocked:     false,
		}
		db.Create(&log)

		payload := map[string]interface{}{
			"ip":             "192.168.1.150",
			"threat":         "XSS",
			"reason":         "Block this IP",
			"permanent":      false,
			"duration_hours": -1,
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/block", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		// Verify log was updated
		var updatedLog models.Log
		db.Where("client_ip = ? AND description = ?", "192.168.1.150", "XSS").First(&updatedLog)
		assert.True(t, updatedLog.Blocked)
		assert.Equal(t, "manual", updatedLog.BlockedBy)
	})
}

func TestUnblockIPWithDB(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(1))
		c.Set("user_email", "test@example.com")
		c.Next()
	})
	router.DELETE("/unblock/:ip", api.NewUnblockIPHandler(db))

	t.Run("unblock IP successfully", func(t *testing.T) {
		// First, block an IP
		blockedIP := models.BlockedIP{
			IPAddress:   "192.168.1.100",
			Description: "XSS",
			Reason:      "Test block",
			Permanent:   true,
		}
		db.Create(&blockedIP)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("DELETE", "/unblock/192.168.1.100?threat=XSS", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "IP unblocked successfully", response["message"])
		assert.Equal(t, "192.168.1.100", response["ip"])
		assert.Equal(t, "XSS", response["threat"])

		// Verify IP was deleted
		var count int64
		db.Model(&models.BlockedIP{}).Where("ip_address = ? AND description = ?", "192.168.1.100", "XSS").Count(&count)
		assert.Equal(t, int64(0), count)
	})

	t.Run("unblock IP - missing threat parameter", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("DELETE", "/unblock/192.168.1.100", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "threat parameter required", response["error"])
	})

	t.Run("unblock IP - updates logs for default threat (restore to auto)", func(t *testing.T) {
		// Create blocked IP and log
		blockedIP := models.BlockedIP{
			IPAddress:   "192.168.1.200",
			Description: "SQL_INJECTION",
			Reason:      "Test block",
			Permanent:   true,
		}
		db.Create(&blockedIP)

		log := models.Log{
			ThreatType:  "SQL_INJECTION",
			Description: "SQL_INJECTION",
			ClientIP:    "192.168.1.200",
			Severity:    "high",
			Method:      "POST",
			URL:         "/test",
			Blocked:     true,
			BlockedBy:   "manual",
		}
		db.Create(&log)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("DELETE", "/unblock/192.168.1.200?threat=SQL_INJECTION", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// Verify log was updated to auto
		var updatedLog models.Log
		db.Where("client_ip = ? AND description = ?", "192.168.1.200", "SQL_INJECTION").First(&updatedLog)
		assert.Equal(t, "auto", updatedLog.BlockedBy)
	})

	t.Run("unblock IP - updates logs for custom threat (remove block)", func(t *testing.T) {
		// Create blocked IP and log with custom threat
		blockedIP := models.BlockedIP{
			IPAddress:   "192.168.1.201",
			Description: "Custom_Rule_Attack",
			Reason:      "Custom threat detected",
			Permanent:   true,
		}
		db.Create(&blockedIP)

		log := models.Log{
			ThreatType:  "Custom_Rule_Attack",
			Description: "Custom_Rule_Attack",
			ClientIP:    "192.168.1.201",
			Severity:    "high",
			Method:      "POST",
			URL:         "/test",
			Blocked:     true,
			BlockedBy:   "manual",
		}
		db.Create(&log)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("DELETE", "/unblock/192.168.1.201?threat=Custom_Rule_Attack", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// Verify log was updated - blocked=false, blocked_by=""
		var updatedLog models.Log
		db.Where("client_ip = ? AND description = ?", "192.168.1.201", "Custom_Rule_Attack").First(&updatedLog)
		assert.False(t, updatedLog.Blocked)
		assert.Equal(t, "", updatedLog.BlockedBy)
	})

	t.Run("unblock IP - all default threats restored to auto", func(t *testing.T) {
		defaultThreats := []string{"XSS", "LFI", "RFI", "COMMAND_INJECTION",
			"XXE", "LDAP_INJECTION", "SSTI", "HTTP_RESPONSE_SPLITTING",
			"PROTOTYPE_POLLUTION", "PATH_TRAVERSAL", "SSRF", "NOSQL_INJECTION"}

		for i, threat := range defaultThreats {
			ip := fmt.Sprintf("192.168.2.%d", i+1)

			// Create blocked IP and log
			blockedIP := models.BlockedIP{
				IPAddress:   ip,
				Description: threat,
				Reason:      "Test block",
				Permanent:   true,
			}
			db.Create(&blockedIP)

			log := models.Log{
				ThreatType:  threat,
				Description: threat,
				ClientIP:    ip,
				Severity:    "high",
				Method:      "GET",
				URL:         "/test",
				Blocked:     true,
				BlockedBy:   "manual",
			}
			db.Create(&log)

			// Unblock
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("DELETE", fmt.Sprintf("/unblock/%s?threat=%s", ip, threat), nil)
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)

			// Verify log was updated to auto
			var updatedLog models.Log
			db.Where("client_ip = ? AND description = ?", ip, threat).First(&updatedLog)
			assert.Equal(t, "auto", updatedLog.BlockedBy, "Threat %s should restore to auto", threat)
		}
	})

	t.Run("unblock IP - non-existent IP returns success", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("DELETE", "/unblock/1.2.3.4?threat=XSS", nil)
		router.ServeHTTP(w, req)

		// GORM Delete doesn't error on non-existent records
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestIsIPBlocked(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	now := time.Now()
	futureTime := now.Add(24 * time.Hour)
	pastTime := now.Add(-24 * time.Hour)

	t.Run("returns true for permanent block", func(t *testing.T) {
		blockedIP := models.BlockedIP{
			IPAddress:   "192.168.1.100",
			Description: "XSS",
			Reason:      "Test block",
			Permanent:   true,
		}
		db.Create(&blockedIP)

		result := api.IsIPBlocked(db, "192.168.1.100", "XSS")
		assert.True(t, result)
	})

	t.Run("returns true for non-expired temporary block", func(t *testing.T) {
		blockedIP := models.BlockedIP{
			IPAddress:   "192.168.1.101",
			Description: "SQL_INJECTION",
			Reason:      "Test block",
			Permanent:   false,
			ExpiresAt:   &futureTime,
		}
		db.Create(&blockedIP)

		result := api.IsIPBlocked(db, "192.168.1.101", "SQL_INJECTION")
		assert.True(t, result)
	})

	t.Run("returns false for expired temporary block", func(t *testing.T) {
		blockedIP := models.BlockedIP{
			IPAddress:   "192.168.1.102",
			Description: "LFI",
			Reason:      "Test block",
			Permanent:   false,
			ExpiresAt:   &pastTime,
		}
		db.Create(&blockedIP)

		result := api.IsIPBlocked(db, "192.168.1.102", "LFI")
		assert.False(t, result)
	})

	t.Run("returns false for non-existent block", func(t *testing.T) {
		result := api.IsIPBlocked(db, "1.2.3.4", "XSS")
		assert.False(t, result)
	})

	t.Run("returns false for different description", func(t *testing.T) {
		blockedIP := models.BlockedIP{
			IPAddress:   "192.168.1.103",
			Description: "XSS",
			Reason:      "Test block",
			Permanent:   true,
		}
		db.Create(&blockedIP)

		// Check with different description
		result := api.IsIPBlocked(db, "192.168.1.103", "SQL_INJECTION")
		assert.False(t, result)
	})

	t.Run("same IP can be blocked for multiple threats", func(t *testing.T) {
		ip := "192.168.1.104"

		blockedIP1 := models.BlockedIP{
			IPAddress:   ip,
			Description: "XSS",
			Reason:      "XSS attack",
			Permanent:   true,
		}
		db.Create(&blockedIP1)

		blockedIP2 := models.BlockedIP{
			IPAddress:   ip,
			Description: "SQL_INJECTION",
			Reason:      "SQL injection",
			Permanent:   true,
		}
		db.Create(&blockedIP2)

		assert.True(t, api.IsIPBlocked(db, ip, "XSS"))
		assert.True(t, api.IsIPBlocked(db, ip, "SQL_INJECTION"))
		assert.False(t, api.IsIPBlocked(db, ip, "LFI"))
	})
}

func TestNewGetBlocklistForWAF(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	now := time.Now()
	futureTime := now.Add(24 * time.Hour)
	pastTime := now.Add(-24 * time.Hour)

	blockedIPs := []models.BlockedIP{
		{
			IPAddress:   "192.168.1.100",
			Description: "XSS",
			Reason:      "Malicious XSS attempt",
			Permanent:   true,
		},
		{
			IPAddress:   "192.168.1.101",
			Description: "SQL_INJECTION",
			Reason:      "SQL injection detected",
			Permanent:   false,
			ExpiresAt:   &futureTime,
		},
		{
			IPAddress:   "192.168.1.102",
			Description: "LFI",
			Reason:      "Path traversal attempt",
			Permanent:   false,
			ExpiresAt:   &pastTime, // Expired
		},
	}

	for _, ip := range blockedIPs {
		assert.NoError(t, db.Create(&ip).Error)
	}

	router := gin.New()
	handler := api.NewGetBlocklistForWAF(db)
	router.GET("/waf/blocklist", handler)

	t.Run("get blocklist for WAF success", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/waf/blocklist", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response struct {
			BlockedIPs []models.BlockedIP `json:"blocked_ips"`
			Count      int                `json:"count"`
		}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, 2, response.Count)
		assert.Equal(t, 2, len(response.BlockedIPs))
	})

	t.Run("factory function creates handler successfully", func(t *testing.T) {
		handler := api.NewGetBlocklistForWAF(db)
		assert.NotNil(t, handler)
	})

	t.Run("get blocklist for WAF empty database", func(t *testing.T) {
		// Clear database
		db.Exec("DELETE FROM blocked_ips")

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/waf/blocklist", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response struct {
			BlockedIPs []models.BlockedIP `json:"blocked_ips"`
			Count      int                `json:"count"`
		}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, 0, response.Count)
	})
}

func TestNewGetWhitelistForWAF(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	whitelistedIPs := []models.WhitelistedIP{
		{
			IPAddress: "10.0.0.1",
			Reason:    "Internal server",
		},
		{
			IPAddress: "10.0.0.2",
			Reason:    "Admin IP",
		},
		{
			IPAddress: "10.0.0.3",
			Reason:    "Trusted partner",
		},
	}

	for _, ip := range whitelistedIPs {
		assert.NoError(t, db.Create(&ip).Error)
	}

	router := gin.New()
	handler := api.NewGetWhitelistForWAF(db)
	router.GET("/waf/whitelist", handler)

	t.Run("get whitelist for WAF success", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/waf/whitelist", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response struct {
			WhitelistedIPs []models.WhitelistedIP `json:"whitelisted_ips"`
			Count          int                    `json:"count"`
		}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, 3, response.Count)
		assert.Equal(t, 3, len(response.WhitelistedIPs))
	})

	t.Run("factory function creates handler successfully", func(t *testing.T) {
		handler := api.NewGetWhitelistForWAF(db)
		assert.NotNil(t, handler)
	})

	t.Run("get whitelist for WAF empty database", func(t *testing.T) {
		// Clear database
		db.Exec("DELETE FROM whitelisted_ips")

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/waf/whitelist", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response struct {
			WhitelistedIPs []models.WhitelistedIP `json:"whitelisted_ips"`
			Count          int                    `json:"count"`
		}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, 0, response.Count)
	})

	t.Run("whitelist ordered by created_at DESC", func(t *testing.T) {
		// Clear and recreate with specific timestamps
		db.Exec("DELETE FROM whitelisted_ips")

		ip1 := models.WhitelistedIP{IPAddress: "10.0.1.1", Reason: "First"}
		ip1.CreatedAt = time.Now().Add(-2 * time.Hour)
		db.Create(&ip1)

		ip2 := models.WhitelistedIP{IPAddress: "10.0.1.2", Reason: "Second"}
		ip2.CreatedAt = time.Now().Add(-1 * time.Hour)
		db.Create(&ip2)

		ip3 := models.WhitelistedIP{IPAddress: "10.0.1.3", Reason: "Third"}
		ip3.CreatedAt = time.Now()
		db.Create(&ip3)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/waf/whitelist", nil)
		router.ServeHTTP(w, req)

		var response struct {
			WhitelistedIPs []models.WhitelistedIP `json:"whitelisted_ips"`
		}
		json.Unmarshal(w.Body.Bytes(), &response)

		// Most recent should be first
		assert.Equal(t, "10.0.1.3", response.WhitelistedIPs[0].IPAddress)
	})
}

func TestBlocklistEdgeCases(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(1))
		c.Set("user_email", "test@example.com")
		c.Next()
	})
	router.POST("/block", api.NewBlockIPHandler(db))
	router.DELETE("/unblock/:ip", api.NewUnblockIPHandler(db))

	t.Run("block IPv6 address", func(t *testing.T) {
		payload := map[string]interface{}{
			"ip":             "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			"threat":         "XSS",
			"reason":         "IPv6 test",
			"permanent":      false,
			"duration_hours": -1,
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/block", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("block IPv6 loopback", func(t *testing.T) {
		payload := map[string]interface{}{
			"ip":             "::1",
			"threat":         "XSS",
			"reason":         "IPv6 loopback test",
			"permanent":      false,
			"duration_hours": -1,
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/block", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Contains(t, response["error"], "loopback")
	})

	t.Run("block IP with whitespace trimming", func(t *testing.T) {
		payload := map[string]interface{}{
			"ip":             "  192.168.1.50  ",
			"threat":         "XSS",
			"reason":         "Test whitespace trimming",
			"permanent":      false,
			"duration_hours": -1,
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/block", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var response struct {
			Entry models.BlockedIP `json:"entry"`
		}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "192.168.1.50", response.Entry.IPAddress)
	})

	t.Run("concurrent blocks for same IP different threats", func(t *testing.T) {
		threats := []string{"XSS", "SQL_INJECTION", "LFI"}

		for _, threat := range threats {
			payload := map[string]interface{}{
				"ip":             "192.168.1.60",
				"threat":         threat,
				"reason":         "Concurrent test for " + threat,
				"permanent":      false,
				"duration_hours": -1,
			}
			body, _ := json.Marshal(payload)

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("POST", "/block", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusCreated, w.Code)
		}

		// Verify all three blocks exist
		var count int64
		db.Model(&models.BlockedIP{}).Where("ip_address = ?", "192.168.1.60").Count(&count)
		assert.Equal(t, int64(3), count)
	})

	t.Run("block with valid special characters in reason", func(t *testing.T) {
		payload := map[string]interface{}{
			"ip":             "192.168.1.70",
			"threat":         "XSS",
			"reason":         "Test-reason_with.special:chars;(valid)/chars",
			"permanent":      false,
			"duration_hours": -1,
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/block", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("block with maximum valid duration", func(t *testing.T) {
		payload := map[string]interface{}{
			"ip":             "192.168.1.80",
			"threat":         "XSS",
			"reason":         "Max duration test",
			"duration_hours": 87600, // 10 years
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/block", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("unblock with empty threat param", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("DELETE", "/unblock/192.168.1.100?threat=", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestBlocklistAuditLogging(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(1))
		c.Set("user_email", "admin@example.com")
		c.Next()
	})
	router.POST("/block", api.NewBlockIPHandler(db))
	router.DELETE("/unblock/:ip", api.NewUnblockIPHandler(db))

	t.Run("block IP creates audit log", func(t *testing.T) {
		payload := map[string]interface{}{
			"ip":             "192.168.1.100",
			"threat":         "XSS",
			"reason":         "Audit log test",
			"permanent":      false,
			"duration_hours": -1,
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/block", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		// Verify audit log was created
		var auditLog models.AuditLog
		err := db.Where("action = ? AND resource_id = ?", "BLOCK_IP", "192.168.1.100").First(&auditLog).Error
		assert.NoError(t, err)
		assert.Equal(t, "BLOCKLIST", auditLog.Category)
		assert.Equal(t, "success", auditLog.Status)
	})

	t.Run("update block IP creates update audit log", func(t *testing.T) {
		// First block
		payload1 := map[string]interface{}{
			"ip":             "192.168.1.101",
			"threat":         "SQL_INJECTION",
			"reason":         "Initial block",
			"permanent":      false,
			"duration_hours": 24,
		}
		body1, _ := json.Marshal(payload1)
		w1 := httptest.NewRecorder()
		req1, _ := http.NewRequest("POST", "/block", bytes.NewBuffer(body1))
		req1.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w1, req1)

		// Update block
		payload2 := map[string]interface{}{
			"ip":             "192.168.1.101",
			"threat":         "SQL_INJECTION",
			"reason":         "Updated block",
			"permanent":      false,
			"duration_hours": -1,
		}
		body2, _ := json.Marshal(payload2)
		w2 := httptest.NewRecorder()
		req2, _ := http.NewRequest("POST", "/block", bytes.NewBuffer(body2))
		req2.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w2, req2)

		assert.Equal(t, http.StatusOK, w2.Code)

		// Verify update audit log was created
		var auditLog models.AuditLog
		err := db.Where("action = ? AND resource_id = ?", "BLOCK_IP_UPDATE", "192.168.1.101").First(&auditLog).Error
		assert.NoError(t, err)
	})

	t.Run("unblock IP creates audit log", func(t *testing.T) {
		// First block
		blockedIP := models.BlockedIP{
			IPAddress:   "192.168.1.102",
			Description: "LFI",
			Reason:      "Test",
			Permanent:   true,
		}
		db.Create(&blockedIP)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("DELETE", "/unblock/192.168.1.102?threat=LFI", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// Verify audit log was created
		var auditLog models.AuditLog
		err := db.Where("action = ? AND resource_id = ?", "UNBLOCK_IP", "192.168.1.102").First(&auditLog).Error
		assert.NoError(t, err)
		assert.Equal(t, "BLOCKLIST", auditLog.Category)
	})

	t.Run("failed block creates error audit log", func(t *testing.T) {
		payload := map[string]interface{}{
			"ip":     "invalid",
			"threat": "XSS",
			"reason": "Test",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/block", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		// Verify error audit log was created
		var auditLog models.AuditLog
		err := db.Where("action = ? AND status = ?", "BLOCK_IP", "failure").First(&auditLog).Error
		assert.NoError(t, err)
		assert.NotEmpty(t, auditLog.Error)
	})
}

func TestBlocklistDatabaseErrors(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	t.Run("GetBlocklist handles database query gracefully on empty result", func(t *testing.T) {
		router := gin.New()
		router.GET("/blocklist", api.GetBlocklist(db))

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/blocklist", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response struct {
			BlockedIPs []models.BlockedIP `json:"blocked_ips"`
			Count      int                `json:"count"`
		}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, 0, response.Count)
	})

	t.Run("NewGetBlocklistForWAF handles empty database", func(t *testing.T) {
		router := gin.New()
		router.GET("/waf/blocklist", api.NewGetBlocklistForWAF(db))

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/waf/blocklist", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("NewGetWhitelistForWAF handles empty database", func(t *testing.T) {
		router := gin.New()
		router.GET("/waf/whitelist", api.NewGetWhitelistForWAF(db))

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/waf/whitelist", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestDeprecatedUnblockIP(t *testing.T) {
	t.Run("deprecated UnblockIP returns error", func(t *testing.T) {
		router := gin.New()
		router.DELETE("/unblock-deprecated", api.UnblockIP)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("DELETE", "/unblock-deprecated", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "use NewUnblockIPHandler", response["error"])
	})
}

func TestGetBlocklistDatabaseError(t *testing.T) {
	db := helpers.SetupTestDB(t)
	helpers.CleanupTestDB(t, db)

	t.Run("GetBlocklist handles database error", func(t *testing.T) {
		router := gin.New()
		router.GET("/blocklist", api.GetBlocklist(db))

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/blocklist", nil)
		router.ServeHTTP(w, req)

		// After closing DB, should get error
		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "Failed to fetch blocked IPs", response["error"])
	})
}

func TestNewGetBlocklistForWAFDatabaseError(t *testing.T) {
	db := helpers.SetupTestDB(t)
	helpers.CleanupTestDB(t, db)

	t.Run("NewGetBlocklistForWAF handles database error", func(t *testing.T) {
		router := gin.New()
		handler := api.NewGetBlocklistForWAF(db)
		router.GET("/waf/blocklist", handler)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/waf/blocklist", nil)
		router.ServeHTTP(w, req)

		// After closing DB, should get error
		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "Failed to fetch blocked IPs", response["error"])
	})
}

func TestNewGetWhitelistForWAFDatabaseError(t *testing.T) {
	db := helpers.SetupTestDB(t)
	helpers.CleanupTestDB(t, db)

	t.Run("NewGetWhitelistForWAF handles database error", func(t *testing.T) {
		router := gin.New()
		handler := api.NewGetWhitelistForWAF(db)
		router.GET("/waf/whitelist", handler)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/waf/whitelist", nil)
		router.ServeHTTP(w, req)

		// After closing DB, should get error
		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "failed to fetch whitelist", response["error"])
	})
}

func TestBlockIPWithDBDatabaseErrors(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(1))
		c.Set("user_email", "test@example.com")
		c.Next()
	})
	router.POST("/block", api.NewBlockIPHandler(db))

	t.Run("block IP - database error on update", func(t *testing.T) {
		// First, create a blocked IP
		blockedIP := models.BlockedIP{
			IPAddress:   "192.168.1.250",
			Description: "XSS",
			Reason:      "Initial block",
			Permanent:   false,
		}
		expiresAt := time.Now().Add(24 * time.Hour)
		blockedIP.ExpiresAt = &expiresAt
		db.Create(&blockedIP)

		// Close the database to trigger error
		helpers.CleanupTestDB(t, db)

		// Try to update the block
		payload := map[string]interface{}{
			"ip":             "192.168.1.250",
			"threat":         "XSS",
			"reason":         "Updated block",
			"permanent":      false,
			"duration_hours": -1,
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/block", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Contains(t, response["error"], "Failed to")
	})
}

func TestBlockIPWithDBDatabaseErrorOnCreate(t *testing.T) {
	db := helpers.SetupTestDB(t)
	helpers.CleanupTestDB(t, db)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(1))
		c.Set("user_email", "test@example.com")
		c.Next()
	})
	router.POST("/block", api.NewBlockIPHandler(db))

	t.Run("block IP - database error on create", func(t *testing.T) {
		payload := map[string]interface{}{
			"ip":             "192.168.1.251",
			"threat":         "XSS",
			"reason":         "Test create error",
			"permanent":      false,
			"duration_hours": -1,
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/block", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Contains(t, response["error"], "Failed to")
	})
}


func TestUnblockIPWithDBErrors(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(1))
		c.Set("user_email", "test@example.com")
		c.Next()
	})
	router.DELETE("/unblock/:ip", api.NewUnblockIPHandler(db))

	t.Run("unblock IP - database error on delete", func(t *testing.T) {
		// First block an IP
		blockedIP := models.BlockedIP{
			IPAddress:   "192.168.1.254",
			Description: "XSS",
			Reason:      "Test",
			Permanent:   true,
		}
		db.Create(&blockedIP)

		// Close database to trigger error
		helpers.CleanupTestDB(t, db)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("DELETE", "/unblock/192.168.1.254?threat=XSS", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Contains(t, response["error"], "Failed to")
	})
}

func TestUnblockIPWithDBLogUpdateErrors(t *testing.T) {
	db := helpers.SetupTestDB(t)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(1))
		c.Set("user_email", "test@example.com")
		c.Next()
	})
	router.DELETE("/unblock/:ip", api.NewUnblockIPHandler(db))

	t.Run("unblock IP - log update error for default threat", func(t *testing.T) {
		// Create blocked IP
		blockedIP := models.BlockedIP{
			IPAddress:   "192.168.1.255",
			Description: "XSS",
			Reason:      "Test",
			Permanent:   true,
		}
		db.Create(&blockedIP)

		// Create log
		log := models.Log{
			ThreatType:  "XSS",
			Description: "XSS",
			ClientIP:    "192.168.1.255",
			Blocked:     true,
			BlockedBy:   "manual",
		}
		db.Create(&log)

		// Close database to trigger error on log update
		helpers.CleanupTestDB(t, db)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("DELETE", "/unblock/192.168.1.255?threat=XSS", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Contains(t, response["error"], "Failed to")
	})
}

func TestUnblockIPWithDBLogUpdateErrorCustomThreat(t *testing.T) {
	db := helpers.SetupTestDB(t)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(1))
		c.Set("user_email", "test@example.com")
		c.Next()
	})
	router.DELETE("/unblock/:ip", api.NewUnblockIPHandler(db))

	t.Run("unblock IP - log update error for custom threat", func(t *testing.T) {
		// Create blocked IP with custom threat
		blockedIP := models.BlockedIP{
			IPAddress:   "192.168.2.1",
			Description: "Custom_Threat",
			Reason:      "Test",
			Permanent:   true,
		}
		db.Create(&blockedIP)

		// Create log
		log := models.Log{
			ThreatType:  "Custom_Threat",
			Description: "Custom_Threat",
			ClientIP:    "192.168.2.1",
			Blocked:     true,
			BlockedBy:   "manual",
		}
		db.Create(&log)

		// Close database to trigger error on log update
		helpers.CleanupTestDB(t, db)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("DELETE", "/unblock/192.168.2.1?threat=Custom_Threat", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Contains(t, response["error"], "Failed to")
	})
}
