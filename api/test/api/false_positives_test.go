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

func TestNewGetFalsePositivesHandler(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	router := gin.New()
	router.GET("/false-positives", api.NewGetFalsePositivesHandler(db))

	t.Run("factory function creates handler successfully", func(t *testing.T) {
		handler := api.NewGetFalsePositivesHandler(db)
		assert.NotNil(t, handler)
	})

	t.Run("get false positives success - returns all entries", func(t *testing.T) {
		// Create test data
		falsePositives := []models.FalsePositive{
			{
				ThreatType:  "XSS",
				Description: "Detected XSS attempt",
				ClientIP:    "192.168.1.100",
				Method:      "GET",
				URL:         "/test",
				Payload:     "<script>alert('xss')</script>",
				UserAgent:   "Mozilla/5.0",
				Status:      "pending",
			},
			{
				ThreatType:  "SQL_INJECTION",
				Description: "SQL injection detected",
				ClientIP:    "192.168.1.101",
				Method:      "POST",
				URL:         "/login",
				Payload:     "' OR '1'='1",
				UserAgent:   "curl/7.64.1",
				Status:      "reviewed",
			},
			{
				ThreatType:  "LFI",
				Description: "Local file inclusion",
				ClientIP:    "192.168.1.102",
				Method:      "GET",
				URL:         "/file",
				Payload:     "../../../../etc/passwd",
				UserAgent:   "Python-urllib/3.8",
				Status:      "whitelisted",
			},
		}

		for _, fp := range falsePositives {
			assert.NoError(t, db.Create(&fp).Error)
		}

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/false-positives", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response struct {
			FalsePositives []models.FalsePositive `json:"false_positives"`
			Count          int                    `json:"count"`
		}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, 3, response.Count)
		assert.Equal(t, 3, len(response.FalsePositives))
	})

	t.Run("get false positives - empty database", func(t *testing.T) {
		// Clear the database
		db.Exec("DELETE FROM false_positives")

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/false-positives", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response struct {
			FalsePositives []models.FalsePositive `json:"false_positives"`
			Count          int                    `json:"count"`
		}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, 0, response.Count)
	})

	t.Run("get false positives - ordered by created_at DESC", func(t *testing.T) {
		// Clear and recreate with specific timestamps
		db.Exec("DELETE FROM false_positives")

		fp1 := models.FalsePositive{
			ThreatType: "XSS",
			ClientIP:   "10.0.0.1",
			Status:     "pending",
		}
		fp1.CreatedAt = time.Now().Add(-2 * time.Hour)
		db.Create(&fp1)

		fp2 := models.FalsePositive{
			ThreatType: "SQL_INJECTION",
			ClientIP:   "10.0.0.2",
			Status:     "pending",
		}
		fp2.CreatedAt = time.Now().Add(-1 * time.Hour)
		db.Create(&fp2)

		fp3 := models.FalsePositive{
			ThreatType: "LFI",
			ClientIP:   "10.0.0.3",
			Status:     "pending",
		}
		fp3.CreatedAt = time.Now()
		db.Create(&fp3)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/false-positives", nil)
		router.ServeHTTP(w, req)

		var response struct {
			FalsePositives []models.FalsePositive `json:"false_positives"`
		}
		json.Unmarshal(w.Body.Bytes(), &response)

		// Most recent should be first
		assert.Equal(t, "10.0.0.3", response.FalsePositives[0].ClientIP)
		assert.Equal(t, "10.0.0.2", response.FalsePositives[1].ClientIP)
		assert.Equal(t, "10.0.0.1", response.FalsePositives[2].ClientIP)
	})
}

func TestGetFalsePositivesDatabaseError(t *testing.T) {
	db := helpers.SetupTestDB(t)
	helpers.CleanupTestDB(t, db)

	t.Run("get false positives - database error", func(t *testing.T) {
		router := gin.New()
		router.GET("/false-positives", api.NewGetFalsePositivesHandler(db))

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/false-positives", nil)
		router.ServeHTTP(w, req)

		// After closing DB, should get error
		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "failed to fetch false positives", response["error"])
	})
}

func TestNewReportFalsePositiveHandler(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		user := &models.User{
			ID:    1,
			Email: "test@example.com",
		}
		c.Set("user", user)
		c.Next()
	})
	router.POST("/false-positives", api.NewReportFalsePositiveHandler(db))

	t.Run("factory function creates handler successfully", func(t *testing.T) {
		handler := api.NewReportFalsePositiveHandler(db)
		assert.NotNil(t, handler)
	})

	t.Run("report false positive success - with user context", func(t *testing.T) {
		payload := map[string]interface{}{
			"threat_type": "XSS",
			"description": "False positive XSS detection",
			"client_ip":   "192.168.1.100",
			"method":      "GET",
			"url":         "/test",
			"payload":     "<script>alert('test')</script>",
			"user_agent":  "Mozilla/5.0",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/false-positives", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var response struct {
			Message string                `json:"message"`
			Entry   models.FalsePositive  `json:"entry"`
		}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, "False positive reported successfully", response.Message)
		assert.Equal(t, "XSS", response.Entry.ThreatType)
		assert.Equal(t, "False positive XSS detection", response.Entry.Description)
		assert.Equal(t, "192.168.1.100", response.Entry.ClientIP)
		assert.Equal(t, "GET", response.Entry.Method)
		assert.Equal(t, "/test", response.Entry.URL)
		assert.Equal(t, "<script>alert('test')</script>", response.Entry.Payload)
		assert.Equal(t, "Mozilla/5.0", response.Entry.UserAgent)
		assert.Equal(t, "pending", response.Entry.Status)

		// Verify entry was created in database
		var dbEntry models.FalsePositive
		err := db.Where("client_ip = ?", "192.168.1.100").First(&dbEntry).Error
		assert.NoError(t, err)
		assert.Equal(t, "XSS", dbEntry.ThreatType)
	})

	t.Run("report false positive success - with audit log", func(t *testing.T) {
		payload := map[string]interface{}{
			"threat_type": "SQL_INJECTION",
			"description": "False positive SQL injection",
			"client_ip":   "192.168.1.200",
			"method":      "POST",
			"url":         "/login",
			"payload":     "SELECT * FROM users",
			"user_agent":  "curl/7.64.1",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/false-positives", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		// Verify audit log was created - get the most recent one with SQL_INJECTION
		var auditLog models.AuditLog
		err := db.Where("action = ? AND category = ? AND description LIKE ?", "REPORT", "FALSE_POSITIVE", "%SQL_INJECTION%192.168.1.200%").Order("created_at DESC").First(&auditLog).Error
		assert.NoError(t, err)
		assert.Equal(t, uint(1), auditLog.UserID)
		assert.Equal(t, "test@example.com", auditLog.UserEmail)
		assert.Equal(t, "success", auditLog.Status)
		assert.Contains(t, auditLog.Description, "SQL_INJECTION")
		assert.Contains(t, auditLog.Description, "192.168.1.200")
	})

	t.Run("report false positive success - minimum required fields", func(t *testing.T) {
		payload := map[string]interface{}{
			"threat_type": "LFI",
			"client_ip":   "192.168.1.150",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/false-positives", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var response struct {
			Entry models.FalsePositive `json:"entry"`
		}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "LFI", response.Entry.ThreatType)
		assert.Equal(t, "192.168.1.150", response.Entry.ClientIP)
		assert.Equal(t, "", response.Entry.Description)
		assert.Equal(t, "", response.Entry.Method)
		assert.Equal(t, "", response.Entry.URL)
	})

	t.Run("report false positive - invalid JSON", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/false-positives", bytes.NewBuffer([]byte("invalid json")))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "Invalid request", response["error"])
	})

	t.Run("report false positive - missing required field threat_type", func(t *testing.T) {
		payload := map[string]interface{}{
			"client_ip":   "192.168.1.100",
			"description": "Test",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/false-positives", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "Invalid request", response["error"])
	})

	t.Run("report false positive - missing required field client_ip", func(t *testing.T) {
		payload := map[string]interface{}{
			"threat_type": "XSS",
			"description": "Test",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/false-positives", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "Invalid request", response["error"])
	})

	t.Run("report false positive - empty threat_type", func(t *testing.T) {
		payload := map[string]interface{}{
			"threat_type": "",
			"client_ip":   "192.168.1.100",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/false-positives", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("report false positive - empty client_ip", func(t *testing.T) {
		payload := map[string]interface{}{
			"threat_type": "XSS",
			"client_ip":   "",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/false-positives", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestReportFalsePositiveSystemContext(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	router := gin.New()
	// No user context - should use system defaults
	router.POST("/false-positives", api.NewReportFalsePositiveHandler(db))

	t.Run("report false positive success - system context (no user)", func(t *testing.T) {
		payload := map[string]interface{}{
			"threat_type": "COMMAND_INJECTION",
			"description": "System reported false positive",
			"client_ip":   "10.0.0.1",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/false-positives", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		// Verify audit log was created with system user
		var auditLog models.AuditLog
		err := db.Where("action = ? AND user_email = ?", "REPORT", "system").First(&auditLog).Error
		assert.NoError(t, err)
		assert.Equal(t, uint(0), auditLog.UserID)
		assert.Equal(t, "system", auditLog.UserEmail)
	})

	t.Run("report false positive - invalid user context type", func(t *testing.T) {
		routerInvalid := gin.New()
		routerInvalid.Use(func(c *gin.Context) {
			// Set invalid user type (not *models.User)
			c.Set("user", "invalid_user_string")
			c.Next()
		})
		routerInvalid.POST("/false-positives", api.NewReportFalsePositiveHandler(db))

		payload := map[string]interface{}{
			"threat_type": "XSS",
			"client_ip":   "10.0.0.2",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/false-positives", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		routerInvalid.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		// Verify audit log was created with system user (fallback)
		var count int64
		db.Model(&models.AuditLog{}).Where("action = ? AND user_email = ?", "REPORT", "system").Count(&count)
		assert.Greater(t, count, int64(0))
	})
}

func TestReportFalsePositiveDatabaseError(t *testing.T) {
	db := helpers.SetupTestDB(t)
	helpers.CleanupTestDB(t, db)

	t.Run("report false positive - database error on create", func(t *testing.T) {
		router := gin.New()
		router.POST("/false-positives", api.NewReportFalsePositiveHandler(db))

		payload := map[string]interface{}{
			"threat_type": "XSS",
			"client_ip":   "192.168.1.100",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/false-positives", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "failed to report false positive", response["error"])
	})
}

func TestNewUpdateFalsePositiveStatusHandler(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	router := gin.New()
	router.PUT("/false-positives/:id/status", api.NewUpdateFalsePositiveStatusHandler(db))

	t.Run("factory function creates handler successfully", func(t *testing.T) {
		handler := api.NewUpdateFalsePositiveStatusHandler(db)
		assert.NotNil(t, handler)
	})

	t.Run("update status to reviewed - success", func(t *testing.T) {
		// Create false positive
		fp := models.FalsePositive{
			ThreatType: "XSS",
			ClientIP:   "192.168.1.100",
			Status:     "pending",
		}
		db.Create(&fp)

		payload := map[string]interface{}{
			"status":       "reviewed",
			"review_notes": "Reviewed and confirmed as false positive",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", fmt.Sprintf("/false-positives/%d/status", fp.ID), bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "Status updated successfully", response["message"])

		// Verify database was updated
		var updatedFP models.FalsePositive
		db.First(&updatedFP, fp.ID)
		assert.Equal(t, "reviewed", updatedFP.Status)
		assert.Equal(t, "Reviewed and confirmed as false positive", updatedFP.ReviewNotes)
		assert.NotNil(t, updatedFP.ReviewedAt)
	})

	t.Run("update status to whitelisted - success", func(t *testing.T) {
		// Create false positive
		fp := models.FalsePositive{
			ThreatType: "SQL_INJECTION",
			ClientIP:   "192.168.1.101",
			Status:     "pending",
		}
		db.Create(&fp)

		payload := map[string]interface{}{
			"status":       "whitelisted",
			"review_notes": "Added to whitelist",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", fmt.Sprintf("/false-positives/%d/status", fp.ID), bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// Verify database was updated
		var updatedFP models.FalsePositive
		db.First(&updatedFP, fp.ID)
		assert.Equal(t, "whitelisted", updatedFP.Status)
		assert.Equal(t, "Added to whitelist", updatedFP.ReviewNotes)
		assert.NotNil(t, updatedFP.ReviewedAt)
	})

	t.Run("update status to pending - success", func(t *testing.T) {
		// Create false positive
		fp := models.FalsePositive{
			ThreatType: "LFI",
			ClientIP:   "192.168.1.102",
			Status:     "reviewed",
		}
		db.Create(&fp)

		payload := map[string]interface{}{
			"status":       "pending",
			"review_notes": "Reopened for review",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", fmt.Sprintf("/false-positives/%d/status", fp.ID), bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// Verify database was updated
		var updatedFP models.FalsePositive
		db.First(&updatedFP, fp.ID)
		assert.Equal(t, "pending", updatedFP.Status)
	})

	t.Run("update status without review_notes - success", func(t *testing.T) {
		// Create false positive
		fp := models.FalsePositive{
			ThreatType: "XSS",
			ClientIP:   "192.168.1.103",
			Status:     "pending",
		}
		db.Create(&fp)

		payload := map[string]interface{}{
			"status": "reviewed",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", fmt.Sprintf("/false-positives/%d/status", fp.ID), bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// Verify database was updated
		var updatedFP models.FalsePositive
		db.First(&updatedFP, fp.ID)
		assert.Equal(t, "reviewed", updatedFP.Status)
		assert.Equal(t, "", updatedFP.ReviewNotes)
	})

	t.Run("update status - invalid ID format", func(t *testing.T) {
		payload := map[string]interface{}{
			"status": "reviewed",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/false-positives/invalid/status", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "Invalid ID", response["error"])
	})

	t.Run("update status - negative ID", func(t *testing.T) {
		payload := map[string]interface{}{
			"status": "reviewed",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/false-positives/-1/status", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("update status - ID too large", func(t *testing.T) {
		payload := map[string]interface{}{
			"status": "reviewed",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/false-positives/99999999999999999999/status", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("update status - invalid JSON", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/false-positives/1/status", bytes.NewBuffer([]byte("invalid json")))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "Invalid request", response["error"])
	})

	t.Run("update status - missing required field status", func(t *testing.T) {
		payload := map[string]interface{}{
			"review_notes": "Test notes",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/false-positives/1/status", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "Invalid request", response["error"])
	})

	t.Run("update status - empty status", func(t *testing.T) {
		payload := map[string]interface{}{
			"status": "",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/false-positives/1/status", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("update status - invalid status value", func(t *testing.T) {
		payload := map[string]interface{}{
			"status": "invalid_status",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/false-positives/1/status", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "Invalid status", response["error"])
	})

	t.Run("update status - status with uppercase (should fail)", func(t *testing.T) {
		payload := map[string]interface{}{
			"status": "REVIEWED",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/false-positives/1/status", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "Invalid status", response["error"])
	})

	t.Run("update status - various invalid statuses", func(t *testing.T) {
		invalidStatuses := []string{
			"approved",
			"rejected",
			"completed",
			"deleted",
			"archived",
			"pending_review",
			"whitelist",
			"blacklisted",
		}

		for _, status := range invalidStatuses {
			payload := map[string]interface{}{
				"status": status,
			}
			body, _ := json.Marshal(payload)

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("PUT", "/false-positives/1/status", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code, "Status '%s' should be invalid", status)

			var response map[string]interface{}
			json.Unmarshal(w.Body.Bytes(), &response)
			assert.Equal(t, "Invalid status", response["error"])
		}
	})
}

func TestUpdateFalsePositiveStatusDatabaseError(t *testing.T) {
	db := helpers.SetupTestDB(t)
	helpers.CleanupTestDB(t, db)

	t.Run("update status - database error", func(t *testing.T) {
		router := gin.New()
		router.PUT("/false-positives/:id/status", api.NewUpdateFalsePositiveStatusHandler(db))

		payload := map[string]interface{}{
			"status": "reviewed",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/false-positives/1/status", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "failed to update false positive", response["error"])
	})
}

func TestNewDeleteFalsePositiveHandler(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	router := gin.New()
	router.DELETE("/false-positives/:id", api.NewDeleteFalsePositiveHandler(db))

	t.Run("factory function creates handler successfully", func(t *testing.T) {
		handler := api.NewDeleteFalsePositiveHandler(db)
		assert.NotNil(t, handler)
	})

	t.Run("delete false positive - success", func(t *testing.T) {
		// Create false positive
		fp := models.FalsePositive{
			ThreatType: "XSS",
			ClientIP:   "192.168.1.100",
			Status:     "pending",
		}
		db.Create(&fp)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("DELETE", fmt.Sprintf("/false-positives/%d", fp.ID), nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "Entry deleted successfully", response["message"])

		// Verify entry was deleted
		var count int64
		db.Model(&models.FalsePositive{}).Where("id = ?", fp.ID).Count(&count)
		assert.Equal(t, int64(0), count)
	})

	t.Run("delete false positive - non-existent ID", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("DELETE", "/false-positives/99999", nil)
		router.ServeHTTP(w, req)

		// GORM Delete doesn't error on non-existent records
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("delete false positive - invalid ID format", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("DELETE", "/false-positives/invalid", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "Invalid ID", response["error"])
	})

	t.Run("delete false positive - negative ID", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("DELETE", "/false-positives/-1", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("delete false positive - ID zero", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("DELETE", "/false-positives/0", nil)
		router.ServeHTTP(w, req)

		// Zero is technically valid for ParseUint, but will not find a record
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("delete false positive - ID too large", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("DELETE", "/false-positives/99999999999999999999", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("delete false positive - multiple deletions", func(t *testing.T) {
		// Create multiple false positives
		fp1 := models.FalsePositive{ThreatType: "XSS", ClientIP: "10.0.0.1", Status: "pending"}
		fp2 := models.FalsePositive{ThreatType: "SQL_INJECTION", ClientIP: "10.0.0.2", Status: "reviewed"}
		fp3 := models.FalsePositive{ThreatType: "LFI", ClientIP: "10.0.0.3", Status: "whitelisted"}
		db.Create(&fp1)
		db.Create(&fp2)
		db.Create(&fp3)

		// Delete all three
		for _, fp := range []models.FalsePositive{fp1, fp2, fp3} {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("DELETE", fmt.Sprintf("/false-positives/%d", fp.ID), nil)
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
		}

		// Verify all were deleted
		var count int64
		db.Model(&models.FalsePositive{}).Where("id IN ?", []uint{fp1.ID, fp2.ID, fp3.ID}).Count(&count)
		assert.Equal(t, int64(0), count)
	})
}

func TestDeleteFalsePositiveDatabaseError(t *testing.T) {
	db := helpers.SetupTestDB(t)
	helpers.CleanupTestDB(t, db)

	t.Run("delete false positive - database error", func(t *testing.T) {
		router := gin.New()
		router.DELETE("/false-positives/:id", api.NewDeleteFalsePositiveHandler(db))

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("DELETE", "/false-positives/1", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "failed to delete false positive", response["error"])
	})
}

func TestFalsePositivesEdgeCases(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	t.Run("report false positive with special characters in payload", func(t *testing.T) {
		router := gin.New()
		router.POST("/false-positives", api.NewReportFalsePositiveHandler(db))

		payload := map[string]interface{}{
			"threat_type": "XSS",
			"client_ip":   "192.168.1.100",
			"payload":     "<script>alert('test');</script>\"'`{}[]()!@#$%^&*",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/false-positives", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("report false positive with very long URL", func(t *testing.T) {
		router := gin.New()
		router.POST("/false-positives", api.NewReportFalsePositiveHandler(db))

		longURL := "/path?param=" + string(make([]byte, 5000))
		payload := map[string]interface{}{
			"threat_type": "SQL_INJECTION",
			"client_ip":   "192.168.1.101",
			"url":         longURL,
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/false-positives", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("report false positive with unicode characters", func(t *testing.T) {
		router := gin.New()
		router.POST("/false-positives", api.NewReportFalsePositiveHandler(db))

		payload := map[string]interface{}{
			"threat_type": "XSS",
			"client_ip":   "192.168.1.102",
			"description": "Test with unicode: 你好世界 مرحبا العالم",
			"payload":     "<script>alert('unicode: 🚀🔥💻')</script>",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/false-positives", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("update status with very long review_notes", func(t *testing.T) {
		router := gin.New()
		router.PUT("/false-positives/:id/status", api.NewUpdateFalsePositiveStatusHandler(db))

		fp := models.FalsePositive{
			ThreatType: "XSS",
			ClientIP:   "192.168.1.103",
			Status:     "pending",
		}
		db.Create(&fp)

		longNotes := string(make([]byte, 10000))
		payload := map[string]interface{}{
			"status":       "reviewed",
			"review_notes": longNotes,
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", fmt.Sprintf("/false-positives/%d/status", fp.ID), bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("report false positive with IPv6 address", func(t *testing.T) {
		router := gin.New()
		router.POST("/false-positives", api.NewReportFalsePositiveHandler(db))

		payload := map[string]interface{}{
			"threat_type": "XSS",
			"client_ip":   "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/false-positives", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("update reviewed_at timestamp is set correctly", func(t *testing.T) {
		router := gin.New()
		router.PUT("/false-positives/:id/status", api.NewUpdateFalsePositiveStatusHandler(db))

		fp := models.FalsePositive{
			ThreatType: "XSS",
			ClientIP:   "192.168.1.104",
			Status:     "pending",
		}
		db.Create(&fp)

		beforeUpdate := time.Now().Add(-1 * time.Second)

		payload := map[string]interface{}{
			"status": "reviewed",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", fmt.Sprintf("/false-positives/%d/status", fp.ID), bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		afterUpdate := time.Now().Add(1 * time.Second)

		// Verify reviewed_at is set and within expected time range
		var updatedFP models.FalsePositive
		db.First(&updatedFP, fp.ID)
		assert.NotNil(t, updatedFP.ReviewedAt)
		assert.True(t, updatedFP.ReviewedAt.After(beforeUpdate))
		assert.True(t, updatedFP.ReviewedAt.Before(afterUpdate))
	})
}

func TestFalsePositivesStatusTransitions(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	router := gin.New()
	router.PUT("/false-positives/:id/status", api.NewUpdateFalsePositiveStatusHandler(db))

	t.Run("status transition: pending -> reviewed -> whitelisted", func(t *testing.T) {
		fp := models.FalsePositive{
			ThreatType: "XSS",
			ClientIP:   "10.0.1.1",
			Status:     "pending",
		}
		db.Create(&fp)

		// pending -> reviewed
		payload := map[string]interface{}{"status": "reviewed"}
		body, _ := json.Marshal(payload)
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", fmt.Sprintf("/false-positives/%d/status", fp.ID), bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		// reviewed -> whitelisted
		payload = map[string]interface{}{"status": "whitelisted"}
		body, _ = json.Marshal(payload)
		w = httptest.NewRecorder()
		req, _ = http.NewRequest("PUT", fmt.Sprintf("/false-positives/%d/status", fp.ID), bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		var updatedFP models.FalsePositive
		db.First(&updatedFP, fp.ID)
		assert.Equal(t, "whitelisted", updatedFP.Status)
	})

	t.Run("status transition: whitelisted -> pending", func(t *testing.T) {
		fp := models.FalsePositive{
			ThreatType: "SQL_INJECTION",
			ClientIP:   "10.0.1.2",
			Status:     "whitelisted",
		}
		db.Create(&fp)

		payload := map[string]interface{}{"status": "pending"}
		body, _ := json.Marshal(payload)
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", fmt.Sprintf("/false-positives/%d/status", fp.ID), bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		var updatedFP models.FalsePositive
		db.First(&updatedFP, fp.ID)
		assert.Equal(t, "pending", updatedFP.Status)
	})
}

func TestFalsePositivesCompleteCoverage(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	t.Run("all handlers work end-to-end", func(t *testing.T) {
		router := gin.New()
		router.Use(func(c *gin.Context) {
			user := &models.User{ID: 1, Email: "admin@example.com"}
			c.Set("user", user)
			c.Next()
		})
		router.GET("/false-positives", api.NewGetFalsePositivesHandler(db))
		router.POST("/false-positives", api.NewReportFalsePositiveHandler(db))
		router.PUT("/false-positives/:id/status", api.NewUpdateFalsePositiveStatusHandler(db))
		router.DELETE("/false-positives/:id", api.NewDeleteFalsePositiveHandler(db))

		// Step 1: List (should be empty)
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/false-positives", nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		// Step 2: Report false positive
		payload := map[string]interface{}{
			"threat_type": "XSS",
			"client_ip":   "192.168.100.1",
			"description": "End-to-end test",
		}
		body, _ := json.Marshal(payload)
		w = httptest.NewRecorder()
		req, _ = http.NewRequest("POST", "/false-positives", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusCreated, w.Code)

		var createResp struct {
			Entry models.FalsePositive `json:"entry"`
		}
		json.Unmarshal(w.Body.Bytes(), &createResp)
		fpID := createResp.Entry.ID

		// Step 3: List (should have 1 entry)
		w = httptest.NewRecorder()
		req, _ = http.NewRequest("GET", "/false-positives", nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
		var listResp struct {
			Count int `json:"count"`
		}
		json.Unmarshal(w.Body.Bytes(), &listResp)
		assert.Equal(t, 1, listResp.Count)

		// Step 4: Update status
		updatePayload := map[string]interface{}{
			"status":       "reviewed",
			"review_notes": "Reviewed in end-to-end test",
		}
		updateBody, _ := json.Marshal(updatePayload)
		w = httptest.NewRecorder()
		req, _ = http.NewRequest("PUT", fmt.Sprintf("/false-positives/%d/status", fpID), bytes.NewBuffer(updateBody))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		// Step 5: Delete
		w = httptest.NewRecorder()
		req, _ = http.NewRequest("DELETE", fmt.Sprintf("/false-positives/%d", fpID), nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		// Step 6: List (should be empty again)
		w = httptest.NewRecorder()
		req, _ = http.NewRequest("GET", "/false-positives", nil)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
		json.Unmarshal(w.Body.Bytes(), &listResp)
		assert.Equal(t, 0, listResp.Count)
	})
}
