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
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	internalapi "github.com/PiCas19/waf-siem-advanced-detection/api/internal/api"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/service"
)

// TestNewGetLogsHandler_Success tests successful log retrieval
func TestNewGetLogsHandler_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockLogRepo := new(MockLogRepository)
	mockAuditLogRepo := new(MockAuditLogRepository)
	mockBlocklistRepo := new(MockBlocklistRepository)

	mockBlocklistRepo.On("IsBlocked", mock.Anything, mock.Anything).Return(false, nil).Maybe()
	mockBlocklistRepo.On("Count", mock.Anything).Return(int64(0), nil).Maybe()
	mockLogRepo.On("Count", mock.Anything).Return(int64(1), nil).Maybe()
	mockLogRepo.On("CountBlocked", mock.Anything).Return(int64(0), nil).Maybe()
	mockAuditLogRepo.On("Count", mock.Anything).Return(int64(0), nil).Maybe()

	logService := service.NewLogService(mockLogRepo)
	auditLogService := service.NewAuditLogService(mockAuditLogRepo)
	blocklistService := service.NewBlocklistService(mockBlocklistRepo, mockLogRepo)

	expectedLogs := []models.Log{
		{
			ID:             1,
			ThreatType:     "XSS",
			Severity:       "high",
			Description:    "XSS attempt",
			ClientIP:       "1.2.3.4",
			ClientIPSource: "real_ip",
			Method:         "GET",
			URL:            "/test",
			Blocked:        true,
			BlockedBy:      "waf",
			CreatedAt:      time.Now(),
		},
	}

	expectedAuditLogs := []models.AuditLog{
		{
			ID:        1,
			UserID:    1,
			UserEmail: "admin@example.com",
			Action:    "LOGIN",
			Status:    "success",
			CreatedAt: time.Now(),
		},
	}

	expectedBlocklist := []models.BlockedIP{
		{
			ID:          1,
			IPAddress:   "5.6.7.8",
			Description: "CustomThreat",
			Permanent:   true,
		},
	}

	mockLogRepo.On("FindPaginated", mock.Anything, 0, 20).
		Return(expectedLogs, int64(1), nil)
	mockAuditLogRepo.On("FindAll", mock.Anything).
		Return(expectedAuditLogs, nil)
	mockBlocklistRepo.On("FindActive", mock.Anything).
		Return(expectedBlocklist, nil)

	handler := internalapi.NewGetLogsHandler(logService, auditLogService, blocklistService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/logs", nil)

	handler(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotNil(t, resp["security_logs"])
	assert.NotNil(t, resp["audit_logs"])

	mockLogRepo.AssertExpectations(t)
	mockAuditLogRepo.AssertExpectations(t)
	mockBlocklistRepo.AssertExpectations(t)
}

// TestNewGetLogsHandler_InvalidParams tests invalid pagination params
func TestNewGetLogsHandler_InvalidParams(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockLogRepo := new(MockLogRepository)
	mockAuditLogRepo := new(MockAuditLogRepository)
	mockBlocklistRepo := new(MockBlocklistRepository)

	mockBlocklistRepo.On("IsBlocked", mock.Anything, mock.Anything).Return(false, nil).Maybe()
	mockBlocklistRepo.On("Count", mock.Anything).Return(int64(0), nil).Maybe()
	mockLogRepo.On("Count", mock.Anything).Return(int64(0), nil).Maybe()

	logService := service.NewLogService(mockLogRepo)
	auditLogService := service.NewAuditLogService(mockAuditLogRepo)
	blocklistService := service.NewBlocklistService(mockBlocklistRepo, mockLogRepo)

	handler := internalapi.NewGetLogsHandler(logService, auditLogService, blocklistService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/logs?limit=invalid", nil)

	handler(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["code"], "INVALID_REQUEST")
}

// TestNewGetLogsHandler_ServiceError tests service error handling
func TestNewGetLogsHandler_ServiceError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockLogRepo := new(MockLogRepository)
	mockAuditLogRepo := new(MockAuditLogRepository)
	mockBlocklistRepo := new(MockBlocklistRepository)

	mockBlocklistRepo.On("IsBlocked", mock.Anything, mock.Anything).Return(false, nil).Maybe()
	mockBlocklistRepo.On("Count", mock.Anything).Return(int64(0), nil).Maybe()
	mockLogRepo.On("Count", mock.Anything).Return(int64(0), nil).Maybe()

	logService := service.NewLogService(mockLogRepo)
	auditLogService := service.NewAuditLogService(mockAuditLogRepo)
	blocklistService := service.NewBlocklistService(mockBlocklistRepo, mockLogRepo)

	mockLogRepo.On("FindPaginated", mock.Anything, 0, 20).
		Return([]models.Log{}, int64(0), fmt.Errorf("database error"))

	handler := internalapi.NewGetLogsHandler(logService, auditLogService, blocklistService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/logs", nil)

	handler(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["message"], "Failed to fetch logs")

	mockLogRepo.AssertExpectations(t)
}

// TestNewGetLogsHandler_AuditLogsError tests that it continues when audit logs fail
func TestNewGetLogsHandler_AuditLogsError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockLogRepo := new(MockLogRepository)
	mockAuditLogRepo := new(MockAuditLogRepository)
	mockBlocklistRepo := new(MockBlocklistRepository)

	mockBlocklistRepo.On("IsBlocked", mock.Anything, mock.Anything).Return(false, nil).Maybe()
	mockBlocklistRepo.On("Count", mock.Anything).Return(int64(0), nil).Maybe()
	mockLogRepo.On("Count", mock.Anything).Return(int64(1), nil).Maybe()
	mockLogRepo.On("CountBlocked", mock.Anything).Return(int64(0), nil).Maybe()
	mockAuditLogRepo.On("Count", mock.Anything).Return(int64(0), nil).Maybe()

	logService := service.NewLogService(mockLogRepo)
	auditLogService := service.NewAuditLogService(mockAuditLogRepo)
	blocklistService := service.NewBlocklistService(mockBlocklistRepo, mockLogRepo)

	expectedLogs := []models.Log{
		{ID: 1, ThreatType: "XSS", ClientIP: "1.2.3.4", Blocked: true},
	}

	mockLogRepo.On("FindPaginated", mock.Anything, 0, 20).
		Return(expectedLogs, int64(1), nil)
	mockAuditLogRepo.On("FindAll", mock.Anything).
		Return([]models.AuditLog{}, fmt.Errorf("audit log error"))
	mockBlocklistRepo.On("FindActive", mock.Anything).
		Return([]models.BlockedIP{}, nil)

	handler := internalapi.NewGetLogsHandler(logService, auditLogService, blocklistService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/logs", nil)

	handler(c)

	// Should still succeed with empty audit logs
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotNil(t, resp["security_logs"])
	// audit_logs should be empty array, not error
	auditLogs := resp["audit_logs"].([]interface{})
	assert.Equal(t, 0, len(auditLogs))

	mockLogRepo.AssertExpectations(t)
	mockAuditLogRepo.AssertExpectations(t)
	mockBlocklistRepo.AssertExpectations(t)
}

// TestNewGetLogsHandler_BlocklistError tests that it continues when blocklist fails
func TestNewGetLogsHandler_BlocklistError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockLogRepo := new(MockLogRepository)
	mockAuditLogRepo := new(MockAuditLogRepository)
	mockBlocklistRepo := new(MockBlocklistRepository)

	mockBlocklistRepo.On("IsBlocked", mock.Anything, mock.Anything).Return(false, nil).Maybe()
	mockBlocklistRepo.On("Count", mock.Anything).Return(int64(0), nil).Maybe()
	mockLogRepo.On("Count", mock.Anything).Return(int64(1), nil).Maybe()
	mockLogRepo.On("CountBlocked", mock.Anything).Return(int64(0), nil).Maybe()
	mockAuditLogRepo.On("Count", mock.Anything).Return(int64(0), nil).Maybe()

	logService := service.NewLogService(mockLogRepo)
	auditLogService := service.NewAuditLogService(mockAuditLogRepo)
	blocklistService := service.NewBlocklistService(mockBlocklistRepo, mockLogRepo)

	expectedLogs := []models.Log{
		{ID: 1, ThreatType: "XSS", ClientIP: "1.2.3.4", Blocked: true},
	}

	mockLogRepo.On("FindPaginated", mock.Anything, 0, 20).
		Return(expectedLogs, int64(1), nil)
	mockAuditLogRepo.On("FindAll", mock.Anything).
		Return([]models.AuditLog{}, nil)
	mockBlocklistRepo.On("FindActive", mock.Anything).
		Return([]models.BlockedIP{}, fmt.Errorf("blocklist error"))

	handler := internalapi.NewGetLogsHandler(logService, auditLogService, blocklistService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/logs", nil)

	handler(c)

	// Should still succeed even if blocklist fails
	assert.Equal(t, http.StatusOK, w.Code)

	mockLogRepo.AssertExpectations(t)
	mockAuditLogRepo.AssertExpectations(t)
	mockBlocklistRepo.AssertExpectations(t)
}

// TestNewGetLogsHandler_DefaultThreatType tests default threat type with auto blocked_by
func TestNewGetLogsHandler_DefaultThreatType(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockLogRepo := new(MockLogRepository)
	mockAuditLogRepo := new(MockAuditLogRepository)
	mockBlocklistRepo := new(MockBlocklistRepository)

	mockBlocklistRepo.On("IsBlocked", mock.Anything, mock.Anything).Return(false, nil).Maybe()
	mockBlocklistRepo.On("Count", mock.Anything).Return(int64(0), nil).Maybe()
	mockLogRepo.On("Count", mock.Anything).Return(int64(1), nil).Maybe()
	mockLogRepo.On("CountBlocked", mock.Anything).Return(int64(0), nil).Maybe()
	mockAuditLogRepo.On("Count", mock.Anything).Return(int64(0), nil).Maybe()

	logService := service.NewLogService(mockLogRepo)
	auditLogService := service.NewAuditLogService(mockAuditLogRepo)
	blocklistService := service.NewBlocklistService(mockBlocklistRepo, mockLogRepo)

	// Test various default threat types
	expectedLogs := []models.Log{
		{ID: 1, ThreatType: "XSS", ClientIP: "1.2.3.4", BlockedBy: "manual", Blocked: true},
		{ID: 2, ThreatType: "SQL_INJECTION", ClientIP: "2.3.4.5", BlockedBy: "", Blocked: false},
		{ID: 3, ThreatType: "LFI", ClientIP: "3.4.5.6", BlockedBy: "manual", Blocked: true},
		{ID: 4, ThreatType: "RFI", ClientIP: "4.5.6.7", BlockedBy: "", Blocked: false},
		{ID: 5, ThreatType: "COMMAND_INJECTION", ClientIP: "5.6.7.8", BlockedBy: "", Blocked: false},
		{ID: 6, ThreatType: "XXE", ClientIP: "6.7.8.9", BlockedBy: "", Blocked: false},
		{ID: 7, ThreatType: "LDAP_INJECTION", ClientIP: "7.8.9.10", BlockedBy: "", Blocked: false},
		{ID: 8, ThreatType: "SSTI", ClientIP: "8.9.10.11", BlockedBy: "", Blocked: false},
		{ID: 9, ThreatType: "HTTP_RESPONSE_SPLITTING", ClientIP: "9.10.11.12", BlockedBy: "", Blocked: false},
		{ID: 10, ThreatType: "PROTOTYPE_POLLUTION", ClientIP: "10.11.12.13", BlockedBy: "", Blocked: false},
		{ID: 11, ThreatType: "PATH_TRAVERSAL", ClientIP: "11.12.13.14", BlockedBy: "", Blocked: false},
		{ID: 12, ThreatType: "SSRF", ClientIP: "12.13.14.15", BlockedBy: "", Blocked: false},
		{ID: 13, ThreatType: "NOSQL_INJECTION", ClientIP: "13.14.15.16", BlockedBy: "", Blocked: false},
	}

	mockLogRepo.On("FindPaginated", mock.Anything, 0, 20).
		Return(expectedLogs, int64(len(expectedLogs)), nil)
	mockAuditLogRepo.On("FindAll", mock.Anything).
		Return([]models.AuditLog{}, nil)
	mockBlocklistRepo.On("FindActive", mock.Anything).
		Return([]models.BlockedIP{}, nil)

	handler := internalapi.NewGetLogsHandler(logService, auditLogService, blocklistService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/logs", nil)

	handler(c)

	assert.Equal(t, http.StatusOK, w.Code)

	mockLogRepo.AssertExpectations(t)
	mockAuditLogRepo.AssertExpectations(t)
	mockBlocklistRepo.AssertExpectations(t)
}

// TestNewGetLogsHandler_CustomThreatType tests custom threat with manual blocked_by
func TestNewGetLogsHandler_CustomThreatType(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockLogRepo := new(MockLogRepository)
	mockAuditLogRepo := new(MockAuditLogRepository)
	mockBlocklistRepo := new(MockBlocklistRepository)

	mockBlocklistRepo.On("IsBlocked", mock.Anything, mock.Anything).Return(false, nil).Maybe()
	mockBlocklistRepo.On("Count", mock.Anything).Return(int64(0), nil).Maybe()
	mockLogRepo.On("Count", mock.Anything).Return(int64(1), nil).Maybe()
	mockLogRepo.On("CountBlocked", mock.Anything).Return(int64(0), nil).Maybe()
	mockAuditLogRepo.On("Count", mock.Anything).Return(int64(0), nil).Maybe()

	logService := service.NewLogService(mockLogRepo)
	auditLogService := service.NewAuditLogService(mockAuditLogRepo)
	blocklistService := service.NewBlocklistService(mockBlocklistRepo, mockLogRepo)

	expectedLogs := []models.Log{
		{ID: 1, ThreatType: "CustomThreat", Description: "Custom", ClientIP: "1.2.3.4", BlockedBy: "", Blocked: false},
		{ID: 2, ThreatType: "CustomThreat2", Description: "", ClientIP: "5.6.7.8", BlockedBy: "", Blocked: false},
	}

	expectedBlocklist := []models.BlockedIP{
		{IPAddress: "1.2.3.4", Description: "Custom"},
		{IPAddress: "5.6.7.8", Description: "CustomThreat2"},
	}

	mockLogRepo.On("FindPaginated", mock.Anything, 0, 20).
		Return(expectedLogs, int64(2), nil)
	mockAuditLogRepo.On("FindAll", mock.Anything).
		Return([]models.AuditLog{}, nil)
	mockBlocklistRepo.On("FindActive", mock.Anything).
		Return(expectedBlocklist, nil)

	handler := internalapi.NewGetLogsHandler(logService, auditLogService, blocklistService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/logs", nil)

	handler(c)

	assert.Equal(t, http.StatusOK, w.Code)

	mockLogRepo.AssertExpectations(t)
	mockAuditLogRepo.AssertExpectations(t)
	mockBlocklistRepo.AssertExpectations(t)
}

// TestNewGetLogsHandler_MissingSeverity tests severity being set when missing
func TestNewGetLogsHandler_MissingSeverity(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockLogRepo := new(MockLogRepository)
	mockAuditLogRepo := new(MockAuditLogRepository)
	mockBlocklistRepo := new(MockBlocklistRepository)

	mockBlocklistRepo.On("IsBlocked", mock.Anything, mock.Anything).Return(false, nil).Maybe()
	mockBlocklistRepo.On("Count", mock.Anything).Return(int64(0), nil).Maybe()
	mockLogRepo.On("Count", mock.Anything).Return(int64(1), nil).Maybe()
	mockLogRepo.On("CountBlocked", mock.Anything).Return(int64(0), nil).Maybe()
	mockAuditLogRepo.On("Count", mock.Anything).Return(int64(0), nil).Maybe()

	logService := service.NewLogService(mockLogRepo)
	auditLogService := service.NewAuditLogService(mockAuditLogRepo)
	blocklistService := service.NewBlocklistService(mockBlocklistRepo, mockLogRepo)

	expectedLogs := []models.Log{
		{ID: 1, ThreatType: "XSS", ClientIP: "1.2.3.4", Severity: "", Blocked: true},
		{ID: 2, ThreatType: "SQL_INJECTION", ClientIP: "2.3.4.5", Severity: "N/A", Blocked: false},
	}

	mockLogRepo.On("FindPaginated", mock.Anything, 0, 20).
		Return(expectedLogs, int64(2), nil)
	mockAuditLogRepo.On("FindAll", mock.Anything).
		Return([]models.AuditLog{}, nil)
	mockBlocklistRepo.On("FindActive", mock.Anything).
		Return([]models.BlockedIP{}, nil)

	handler := internalapi.NewGetLogsHandler(logService, auditLogService, blocklistService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/logs", nil)

	handler(c)

	assert.Equal(t, http.StatusOK, w.Code)

	mockLogRepo.AssertExpectations(t)
	mockAuditLogRepo.AssertExpectations(t)
	mockBlocklistRepo.AssertExpectations(t)
}

// TestNewUpdateThreatBlockStatusHandler_SuccessBlock tests successful block
func TestNewUpdateThreatBlockStatusHandler_SuccessBlock(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockLogRepo := new(MockLogRepository)
	logService := service.NewLogService(mockLogRepo)

	mockLogRepo.On("UpdateByIPAndDescription", mock.Anything, "1.2.3.4", "XSS", mock.MatchedBy(func(updates map[string]interface{}) bool {
		return updates["blocked"] == true && updates["blocked_by"] == "manual"
	})).Return(nil)

	mockLogRepo.On("FindByIP", mock.Anything, "1.2.3.4").
		Return([]models.Log{{ID: 1, ThreatType: "XSS", Description: "XSS", ClientIP: "1.2.3.4"}}, nil)

	handler := internalapi.NewUpdateThreatBlockStatusHandler(logService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("PUT", "/logs/threat-block-status", bytes.NewBufferString(`{
		"ip": "1.2.3.4",
		"description": "XSS",
		"blocked": true,
		"blocked_by": "manual"
	}`))
	c.Request.Header.Set("Content-Type", "application/json")

	handler(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["message"], "Threat block status updated successfully")

	mockLogRepo.AssertExpectations(t)
}

// TestNewUpdateThreatBlockStatusHandler_SuccessUnblock tests successful unblock
func TestNewUpdateThreatBlockStatusHandler_SuccessUnblock(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockLogRepo := new(MockLogRepository)
	logService := service.NewLogService(mockLogRepo)

	mockLogRepo.On("UpdateByIPAndDescription", mock.Anything, "1.2.3.4", "XSS", mock.MatchedBy(func(updates map[string]interface{}) bool {
		return updates["blocked"] == false && updates["blocked_by"] == ""
	})).Return(nil)

	mockLogRepo.On("FindByIP", mock.Anything, "1.2.3.4").
		Return([]models.Log{{ID: 1, ThreatType: "XSS", Description: "XSS", ClientIP: "1.2.3.4"}}, nil)

	handler := internalapi.NewUpdateThreatBlockStatusHandler(logService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("PUT", "/logs/threat-block-status", bytes.NewBufferString(`{
		"ip": "1.2.3.4",
		"description": "XSS",
		"blocked": false,
		"blocked_by": ""
	}`))
	c.Request.Header.Set("Content-Type", "application/json")

	handler(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["message"], "Threat block status updated successfully")

	mockLogRepo.AssertExpectations(t)
}

// TestNewUpdateThreatBlockStatusHandler_InvalidJSON tests invalid JSON handling
func TestNewUpdateThreatBlockStatusHandler_InvalidJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockLogRepo := new(MockLogRepository)
	logService := service.NewLogService(mockLogRepo)

	handler := internalapi.NewUpdateThreatBlockStatusHandler(logService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("PUT", "/logs/threat-block-status", bytes.NewBufferString(`{invalid json`))
	c.Request.Header.Set("Content-Type", "application/json")

	handler(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestNewUpdateThreatBlockStatusHandler_MissingFields tests missing required fields
func TestNewUpdateThreatBlockStatusHandler_MissingFields(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockLogRepo := new(MockLogRepository)
	logService := service.NewLogService(mockLogRepo)

	handler := internalapi.NewUpdateThreatBlockStatusHandler(logService)

	tests := []struct {
		name string
		body string
	}{
		{"Missing IP", `{"description": "XSS", "blocked": true}`},
		{"Missing Description", `{"ip": "1.2.3.4", "blocked": true}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("PUT", "/logs/threat-block-status", bytes.NewBufferString(tt.body))
			c.Request.Header.Set("Content-Type", "application/json")

			handler(c)

			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

// TestNewUpdateThreatBlockStatusHandler_ServiceError tests service error
func TestNewUpdateThreatBlockStatusHandler_ServiceError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockLogRepo := new(MockLogRepository)
	logService := service.NewLogService(mockLogRepo)

	mockLogRepo.On("UpdateByIPAndDescription", mock.Anything, "1.2.3.4", "XSS", mock.Anything).
		Return(fmt.Errorf("database error"))

	handler := internalapi.NewUpdateThreatBlockStatusHandler(logService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("PUT", "/logs/threat-block-status", bytes.NewBufferString(`{
		"ip": "1.2.3.4",
		"description": "XSS",
		"blocked": true,
		"blocked_by": "manual"
	}`))
	c.Request.Header.Set("Content-Type", "application/json")

	handler(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["message"], "Failed to update threat block status")

	mockLogRepo.AssertExpectations(t)
}

// TestNewUpdateThreatBlockStatusHandler_LogToWAFFileError tests WAF log error handling (should continue)
func TestNewUpdateThreatBlockStatusHandler_LogToWAFFileError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockLogRepo := new(MockLogRepository)
	logService := service.NewLogService(mockLogRepo)

	mockLogRepo.On("UpdateByIPAndDescription", mock.Anything, "1.2.3.4", "XSS", mock.Anything).
		Return(nil)

	// logToWAFFile will fail because we can't write to /var/log/caddy in test
	// But the handler should still return success
	mockLogRepo.On("FindByIP", mock.Anything, "1.2.3.4").
		Return([]models.Log{}, fmt.Errorf("not found"))

	handler := internalapi.NewUpdateThreatBlockStatusHandler(logService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("PUT", "/logs/threat-block-status", bytes.NewBufferString(`{
		"ip": "1.2.3.4",
		"description": "XSS",
		"blocked": true,
		"blocked_by": "manual"
	}`))
	c.Request.Header.Set("Content-Type", "application/json")

	handler(c)

	// Should still succeed even if WAF logging fails
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["message"], "Threat block status updated successfully")

	mockLogRepo.AssertExpectations(t)
}
