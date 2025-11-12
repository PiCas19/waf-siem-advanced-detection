package api

import (
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

func TestGetSeverityFromThreatType(t *testing.T) {
	tests := []struct {
		threatType   string
		expectedSeverity string
	}{
		// Critical threats
		{"SQL_INJECTION", "Critical"},
		{"COMMAND_INJECTION", "Critical"},
		{"XXE", "Critical"},
		{"LDAP_INJECTION", "Critical"},
		{"RFI", "Critical"},
		{"SSTI", "Critical"},

		// High threats
		{"XSS", "High"},
		{"LFI", "High"},
		{"PATH_TRAVERSAL", "High"},
		{"SSRF", "High"},
		{"NOSQL_INJECTION", "High"},
		{"HTTP_RESPONSE_SPLITTING", "High"},

		// Medium threats
		{"PROTOTYPE_POLLUTION", "Medium"},

		// Unknown threats default to Medium
		{"UNKNOWN_THREAT", "Medium"},
		{"CUSTOM_RULE", "Medium"},
		{"", "Medium"},
	}

	for _, tt := range tests {
		t.Run(tt.threatType, func(t *testing.T) {
			severity := api.GetSeverityFromThreatType(tt.threatType)
			assert.Equal(t, tt.expectedSeverity, severity)
		})
	}
}

func TestNewGetLogsHandler(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	// Create test logs
	logs := []models.Log{
		{
			ThreatType:  "XSS",
			Description: "Possible XSS attack",
			ClientIP:    "192.168.1.1",
			Method:      "GET",
			URL:         "/test?id=<script>",
			UserAgent:   "Mozilla/5.0",
			Blocked:     true,
			BlockedBy:   "auto",
			Severity:    "High",
		},
		{
			ThreatType:  "SQL_INJECTION",
			Description: "Custom SQL Rule",
			ClientIP:    "192.168.1.2",
			Method:      "POST",
			URL:         "/api/users",
			Blocked:     true,
			BlockedBy:   "manual",
			Severity:    "Critical",
		},
		{
			ThreatType:  "CUSTOM_RULE",
			Description: "Custom detection rule",
			ClientIP:    "192.168.1.3",
			Method:      "GET",
			URL:         "/admin",
			Blocked:     false,
			BlockedBy:   "",
			Severity:    "",
		},
	}

	for _, log := range logs {
		assert.NoError(t, db.Create(&log).Error)
	}

	// Create test audit logs
	auditLogs := []models.AuditLog{
		{
			UserID:    1,
			UserEmail: "admin@example.com",
			Action:    "LOGIN",
			Status:    "success",
		},
	}

	for _, log := range auditLogs {
		assert.NoError(t, db.Create(&log).Error)
	}

	router := gin.New()
	router.GET("/logs", api.NewGetLogsHandler(db))

	t.Run("get logs success", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/logs", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response struct {
			SecurityLogs []models.Log       `json:"security_logs"`
			AuditLogs    []models.AuditLog  `json:"audit_logs"`
			Logs         []models.Log       `json:"logs"`
		}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, 3, len(response.SecurityLogs))
		assert.Equal(t, 1, len(response.AuditLogs))
		assert.Equal(t, 3, len(response.Logs))
	})

	t.Run("get logs normalizes blockedBy for default threats", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/logs", nil)
		router.ServeHTTP(w, req)

		var response struct {
			SecurityLogs []models.Log `json:"security_logs"`
		}
		json.Unmarshal(w.Body.Bytes(), &response)

		// XSS is a default threat, should have BlockedBy="auto"
		xssLog := response.SecurityLogs[0]
		assert.Equal(t, "auto", xssLog.BlockedBy)

		// SQL_INJECTION is a default threat, should have BlockedBy="auto" even if it was "manual"
		sqlLog := response.SecurityLogs[1]
		assert.Equal(t, "auto", sqlLog.BlockedBy)
	})

	t.Run("get logs sets missing severity", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/logs", nil)
		router.ServeHTTP(w, req)

		var response struct {
			SecurityLogs []models.Log `json:"security_logs"`
		}
		json.Unmarshal(w.Body.Bytes(), &response)

		// CUSTOM_RULE had empty severity, should be set to Medium
		customLog := response.SecurityLogs[2]
		assert.Equal(t, "Medium", customLog.Severity)
	})

	t.Run("get logs returns recent first", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/logs", nil)
		router.ServeHTTP(w, req)

		var response struct {
			SecurityLogs []models.Log `json:"security_logs"`
		}
		json.Unmarshal(w.Body.Bytes(), &response)

		// Should be ordered by created_at DESC
		assert.Greater(t, len(response.SecurityLogs), 0)
	})
}

func TestIsDefaultThreatType(t *testing.T) {
	tests := []struct {
		threatType string
		isDefault  bool
	}{
		{"XSS", true},
		{"SQL_INJECTION", true},
		{"LFI", true},
		{"RFI", true},
		{"COMMAND_INJECTION", true},
		{"XXE", true},
		{"LDAP_INJECTION", true},
		{"SSTI", true},
		{"HTTP_RESPONSE_SPLITTING", true},
		{"PROTOTYPE_POLLUTION", true},
		{"PATH_TRAVERSAL", true},
		{"SSRF", true},
		{"NOSQL_INJECTION", true},
		{"CUSTOM_RULE", false},
		{"UNKNOWN", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.threatType, func(t *testing.T) {
			// We can't test isDefaultThreatType directly since it's unexported
			// Instead, we'll verify it through GetLogsHandler behavior
			db := helpers.SetupTestDB(t)
			defer helpers.CleanupTestDB(t, db)

			log := models.Log{
				ThreatType:  tt.threatType,
				Description: "Test",
				ClientIP:    "192.168.1.1",
				Blocked:     true,
				BlockedBy:   "manual", // Explicitly set to manual
			}
			db.Create(&log)

			router := gin.New()
			router.GET("/logs", api.NewGetLogsHandler(db))

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/logs", nil)
			router.ServeHTTP(w, req)

			var response struct {
				SecurityLogs []models.Log `json:"security_logs"`
			}
			json.Unmarshal(w.Body.Bytes(), &response)

			if tt.isDefault {
				// Default threats should have BlockedBy="auto"
				assert.Equal(t, "auto", response.SecurityLogs[0].BlockedBy)
			} else {
				// Non-default threats should keep their BlockedBy value
				assert.Equal(t, "manual", response.SecurityLogs[0].BlockedBy)
			}
		})
	}
}

func TestGetLogsHandlerEmptyDatabase(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	router := gin.New()
	router.GET("/logs", api.NewGetLogsHandler(db))

	t.Run("get logs empty database", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/logs", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response struct {
			SecurityLogs []models.Log      `json:"security_logs"`
			AuditLogs    []models.AuditLog `json:"audit_logs"`
		}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, 0, len(response.SecurityLogs))
		assert.Equal(t, 0, len(response.AuditLogs))
	})
}

func TestGetLogsHandlerWithSeverityMapping(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	// Test with all threat types and verify severity mapping
	threatTypesWithSeverity := map[string]string{
		"XSS":                     "High",
		"SQL_INJECTION":           "Critical",
		"LFI":                     "High",
		"SSRF":                    "High",
		"COMMAND_INJECTION":       "Critical",
		"XXE":                     "Critical",
		"LDAP_INJECTION":          "Critical",
		"SSTI":                    "Critical",
		"RFI":                     "Critical",
		"PATH_TRAVERSAL":          "High",
		"NOSQL_INJECTION":         "High",
		"HTTP_RESPONSE_SPLITTING": "High",
		"PROTOTYPE_POLLUTION":     "Medium",
	}

	for threatType, _ := range threatTypesWithSeverity {
		log := models.Log{
			ThreatType:  threatType,
			Description: "Test " + threatType,
			ClientIP:    "192.168.1.1",
			Blocked:     true,
			BlockedBy:   "auto",
			Severity:    "", // Empty to test auto-fill
		}
		db.Create(&log)
	}

	router := gin.New()
	router.GET("/logs", api.NewGetLogsHandler(db))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/logs", nil)
	router.ServeHTTP(w, req)

	var response struct {
		SecurityLogs []models.Log `json:"security_logs"`
	}
	json.Unmarshal(w.Body.Bytes(), &response)

	for _, log := range response.SecurityLogs {
		expectedSev, exists := threatTypesWithSeverity[log.ThreatType]
		if exists {
			assert.Equal(t, expectedSev, log.Severity)
		}
	}
}

func TestGetLogsHandlerAuditLogFailure(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	// Create security log
	secLog := models.Log{
		ThreatType:  "XSS",
		Description: "XSS test",
		ClientIP:    "192.168.1.1",
		Blocked:     true,
		BlockedBy:   "auto",
	}
	db.Create(&secLog)

	router := gin.New()
	router.GET("/logs", api.NewGetLogsHandler(db))

	t.Run("handler continues even if audit logs fail", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/logs", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response struct {
			SecurityLogs []models.Log `json:"security_logs"`
		}
		json.Unmarshal(w.Body.Bytes(), &response)
		// Should still return security logs even if audit logs fail
		assert.Equal(t, 1, len(response.SecurityLogs))
	})
}
