package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/api"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/test/helpers"
)

func TestNewGetAuditLogsHandler(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	// Seed test audit logs
	auditLogs := []models.AuditLog{
		{
			UserID:       1,
			UserEmail:    "user1@example.com",
			Action:       "LOGIN",
			Category:     "AUTH",
			Description:  "User login",
			Status:       "success",
			IPAddress:    "192.168.1.1",
			CreatedAt:    time.Now(),
		},
		{
			UserID:       2,
			UserEmail:    "user2@example.com",
			Action:       "CREATE_RULE",
			Category:     "RULES",
			Description:  "Created custom rule",
			Status:       "success",
			IPAddress:    "192.168.1.2",
			CreatedAt:    time.Now().Add(-1 * time.Hour),
		},
		{
			UserID:       1,
			UserEmail:    "user1@example.com",
			Action:       "BLOCK_IP",
			Category:     "BLOCKLIST",
			Description:  "Blocked IP",
			Status:       "failure",
			Error:        "Database error",
			IPAddress:    "192.168.1.1",
			CreatedAt:    time.Now().Add(-2 * time.Hour),
		},
	}

	for _, log := range auditLogs {
		assert.NoError(t, db.Create(&log).Error)
	}

	router := gin.New()
	router.GET("/audit-logs", api.NewGetAuditLogsHandler(db))

	t.Run("get audit logs success", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/audit-logs", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response struct {
			AuditLogs  []models.AuditLog `json:"audit_logs"`
			Pagination map[string]interface{} `json:"pagination"`
		}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, 3, len(response.AuditLogs))
		assert.NotNil(t, response.Pagination)
	})

	t.Run("get audit logs with pagination", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/audit-logs?page=1&limit=2", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response struct {
			AuditLogs  []models.AuditLog `json:"audit_logs"`
			Pagination map[string]interface{} `json:"pagination"`
		}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, 2, len(response.AuditLogs))
		assert.Equal(t, float64(1), response.Pagination["page"])
		assert.Equal(t, float64(2), response.Pagination["limit"])
	})

	t.Run("get audit logs filter by action", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/audit-logs?action=LOGIN", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response struct {
			AuditLogs []models.AuditLog `json:"audit_logs"`
		}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, 1, len(response.AuditLogs))
		assert.Equal(t, "LOGIN", response.AuditLogs[0].Action)
	})

	t.Run("get audit logs filter by category", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/audit-logs?category=RULES", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response struct {
			AuditLogs []models.AuditLog `json:"audit_logs"`
		}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, 1, len(response.AuditLogs))
		assert.Equal(t, "RULES", response.AuditLogs[0].Category)
	})

	t.Run("get audit logs filter by status", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/audit-logs?status=failure", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response struct {
			AuditLogs []models.AuditLog `json:"audit_logs"`
		}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, 1, len(response.AuditLogs))
		assert.Equal(t, "failure", response.AuditLogs[0].Status)
	})

	t.Run("get audit logs filter by user_id", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/audit-logs?user_id=1", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response struct {
			AuditLogs []models.AuditLog `json:"audit_logs"`
		}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, 2, len(response.AuditLogs))
	})

	t.Run("get audit logs with invalid page number", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/audit-logs?page=invalid", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response struct {
			AuditLogs  []models.AuditLog `json:"audit_logs"`
			Pagination map[string]interface{} `json:"pagination"`
		}
		json.Unmarshal(w.Body.Bytes(), &response)
		// Should default to page 1
		assert.Equal(t, float64(1), response.Pagination["page"])
	})

	t.Run("get audit logs with limit exceed max", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/audit-logs?limit=1000", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response struct {
			Pagination map[string]interface{} `json:"pagination"`
		}
		json.Unmarshal(w.Body.Bytes(), &response)
		// Should be capped at 500
		assert.Equal(t, float64(500), response.Pagination["limit"])
	})

	t.Run("get audit logs orders by created_at DESC", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/audit-logs", nil)
		router.ServeHTTP(w, req)

		var response struct {
			AuditLogs []models.AuditLog `json:"audit_logs"`
		}
		json.Unmarshal(w.Body.Bytes(), &response)
		// First log should be most recent
		assert.Equal(t, "LOGIN", response.AuditLogs[0].Action)
	})
}

func TestNewGetAuditLogStatsHandler(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	// Seed test audit logs
	auditLogs := []models.AuditLog{
		{
			UserID:    1,
			UserEmail: "user1@example.com",
			Action:    "LOGIN",
			Category:  "AUTH",
			Status:    "success",
		},
		{
			UserID:    2,
			UserEmail: "user2@example.com",
			Action:    "LOGIN",
			Category:  "AUTH",
			Status:    "success",
		},
		{
			UserID:    1,
			UserEmail: "user1@example.com",
			Action:    "CREATE_RULE",
			Category:  "RULES",
			Status:    "success",
		},
		{
			UserID:    3,
			UserEmail: "user3@example.com",
			Action:    "BLOCK_IP",
			Category:  "BLOCKLIST",
			Status:    "failure",
		},
		{
			UserID:    1,
			UserEmail: "user1@example.com",
			Action:    "LOGIN",
			Category:  "AUTH",
			Status:    "failure",
		},
	}

	for _, log := range auditLogs {
		assert.NoError(t, db.Create(&log).Error)
	}

	router := gin.New()
	router.GET("/audit-logs/stats", api.NewGetAuditLogStatsHandler(db))

	t.Run("get audit log stats success", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/audit-logs/stats", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response struct {
			TotalActions      int64 `json:"total_actions"`
			SuccessfulActions int64 `json:"successful_actions"`
			FailedActions     int64 `json:"failed_actions"`
			ActionBreakdown   []map[string]interface{} `json:"action_breakdown"`
			UserActivity      []map[string]interface{} `json:"user_activity"`
		}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))

		assert.Equal(t, int64(5), response.TotalActions)
		assert.Equal(t, int64(4), response.SuccessfulActions)
		assert.Equal(t, int64(1), response.FailedActions)
		assert.NotNil(t, response.ActionBreakdown)
		assert.NotNil(t, response.UserActivity)
	})

	t.Run("get audit log stats action breakdown", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/audit-logs/stats", nil)
		router.ServeHTTP(w, req)

		var response struct {
			ActionBreakdown []struct {
				Action string
				Count  int64
			} `json:"action_breakdown"`
		}
		json.Unmarshal(w.Body.Bytes(), &response)

		// LOGIN should be the most frequent
		assert.Greater(t, len(response.ActionBreakdown), 0)
		assert.Equal(t, "LOGIN", response.ActionBreakdown[0].Action)
		assert.Equal(t, int64(3), response.ActionBreakdown[0].Count)
	})

	t.Run("get audit log stats user activity", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/audit-logs/stats", nil)
		router.ServeHTTP(w, req)

		var response struct {
			UserActivity []struct {
				UserEmail string
				Count     int64
			} `json:"user_activity"`
		}
		json.Unmarshal(w.Body.Bytes(), &response)

		// user1@example.com should have the most activity
		assert.Greater(t, len(response.UserActivity), 0)
		assert.Equal(t, "user1@example.com", response.UserActivity[0].UserEmail)
		assert.Equal(t, int64(3), response.UserActivity[0].Count)
	})
}

func TestAuditLogsHandlerEmptyDatabase(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	router := gin.New()
	router.GET("/audit-logs", api.NewGetAuditLogsHandler(db))
	router.GET("/audit-logs/stats", api.NewGetAuditLogStatsHandler(db))

	t.Run("get audit logs empty database", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/audit-logs", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response struct {
			AuditLogs []models.AuditLog `json:"audit_logs"`
			Pagination map[string]interface{} `json:"pagination"`
		}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, 0, len(response.AuditLogs))
		assert.Equal(t, int64(0), response.Pagination["total"])
	})

	t.Run("get audit log stats empty database", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/audit-logs/stats", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response struct {
			TotalActions      int64 `json:"total_actions"`
			SuccessfulActions int64 `json:"successful_actions"`
			FailedActions     int64 `json:"failed_actions"`
		}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, int64(0), response.TotalActions)
		assert.Equal(t, int64(0), response.SuccessfulActions)
		assert.Equal(t, int64(0), response.FailedActions)
	})
}

func TestAuditLogsPagination(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	// Create 50 audit logs
	for i := 1; i <= 50; i++ {
		log := models.AuditLog{
			UserID:    uint(i),
			UserEmail: "user" + strconv.Itoa(i) + "@example.com",
			Action:    "ACTION_" + strconv.Itoa(i),
			Category:  "TEST",
			Status:    "success",
		}
		assert.NoError(t, db.Create(&log).Error)
	}

	router := gin.New()
	router.GET("/audit-logs", api.NewGetAuditLogsHandler(db))

	t.Run("pagination page 1", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/audit-logs?page=1&limit=10", nil)
		router.ServeHTTP(w, req)

		var response struct {
			Pagination struct {
				Page       int   `json:"page"`
				Limit      int   `json:"limit"`
				Total      int64 `json:"total"`
				TotalPages int   `json:"total_pages"`
			} `json:"pagination"`
		}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, 1, response.Pagination.Page)
		assert.Equal(t, 10, response.Pagination.Limit)
		assert.Equal(t, int64(50), response.Pagination.Total)
		assert.Equal(t, 5, response.Pagination.TotalPages)
	})

	t.Run("pagination page 2", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/audit-logs?page=2&limit=10", nil)
		router.ServeHTTP(w, req)

		var response struct {
			AuditLogs []models.AuditLog `json:"audit_logs"`
		}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, 10, len(response.AuditLogs))
	})
}
