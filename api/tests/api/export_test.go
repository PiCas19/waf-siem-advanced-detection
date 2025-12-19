package api

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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

// TestNewExportLogsHandler_JSON tests successful JSON export
func TestNewExportLogsHandler_JSON(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockLogRepo := new(MockLogRepository)
	logService := service.NewLogService(mockLogRepo)

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
			UserAgent:      "Mozilla",
			Payload:        "<script>alert('xss')</script>",
			Blocked:        true,
			BlockedBy:      "waf",
			CreatedAt:      time.Now(),
		},
	}

	mockLogRepo.On("FindPaginated", mock.Anything, 0, 1000).
		Return(expectedLogs, int64(1), nil)

	handler := internalapi.NewExportLogsHandler(logService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/export/logs?format=json", nil)

	handler(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")
	assert.Contains(t, w.Header().Get("Content-Disposition"), "security_logs_")
	assert.Contains(t, w.Header().Get("Content-Disposition"), ".json")

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, float64(1), resp["count"])

	mockLogRepo.AssertExpectations(t)
}

// TestNewExportLogsHandler_CSV tests successful CSV export
func TestNewExportLogsHandler_CSV(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockLogRepo := new(MockLogRepository)
	logService := service.NewLogService(mockLogRepo)

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
			UserAgent:      "Mozilla",
			Payload:        "<script>alert('xss')</script>",
			Blocked:        true,
			BlockedBy:      "waf",
			CreatedAt:      time.Now(),
		},
	}

	mockLogRepo.On("FindPaginated", mock.Anything, 0, 1000).
		Return(expectedLogs, int64(1), nil)

	handler := internalapi.NewExportLogsHandler(logService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/export/logs?format=csv", nil)

	handler(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/csv")
	assert.Contains(t, w.Header().Get("Content-Disposition"), "security_logs_")
	assert.Contains(t, w.Header().Get("Content-Disposition"), ".csv")

	// Verify CSV structure
	reader := csv.NewReader(strings.NewReader(w.Body.String()))
	records, err := reader.ReadAll()
	require.NoError(t, err)
	assert.Greater(t, len(records), 0) // At least header row

	mockLogRepo.AssertExpectations(t)
}

// TestNewExportLogsHandler_XML tests successful XML export
func TestNewExportLogsHandler_XML(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockLogRepo := new(MockLogRepository)
	logService := service.NewLogService(mockLogRepo)

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
			UserAgent:      "Mozilla",
			Payload:        "<script>alert('xss')</script>",
			Blocked:        true,
			BlockedBy:      "waf",
			CreatedAt:      time.Now(),
		},
	}

	mockLogRepo.On("FindPaginated", mock.Anything, 0, 1000).
		Return(expectedLogs, int64(1), nil)

	handler := internalapi.NewExportLogsHandler(logService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/export/logs?format=xml", nil)

	handler(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/xml")
	assert.Contains(t, w.Header().Get("Content-Disposition"), "security_logs_")
	assert.Contains(t, w.Header().Get("Content-Disposition"), ".xml")

	// Verify XML structure
	body := w.Body.String()
	assert.Contains(t, body, "<?xml version=")
	assert.Contains(t, body, "<logs>")
	assert.Contains(t, body, "</logs>")

	mockLogRepo.AssertExpectations(t)
}

// TestNewExportLogsHandler_InvalidFormat tests invalid format handling
func TestNewExportLogsHandler_InvalidFormat(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockLogRepo := new(MockLogRepository)
	logService := service.NewLogService(mockLogRepo)

	handler := internalapi.NewExportLogsHandler(logService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/export/logs?format=pdf", nil)

	handler(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["message"], "Invalid format")
}

// TestNewExportLogsHandler_InvalidLimit tests invalid limit handling
func TestNewExportLogsHandler_InvalidLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockLogRepo := new(MockLogRepository)
	logService := service.NewLogService(mockLogRepo)

	handler := internalapi.NewExportLogsHandler(logService)

	tests := []struct {
		name  string
		limit string
	}{
		{"Limit too small", "0"},
		{"Limit too large", "20000"},
		{"Invalid number", "abc"},
		{"Negative limit", "-10"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("GET", fmt.Sprintf("/export/logs?format=json&limit=%s", tt.limit), nil)

			handler(c)

			assert.Equal(t, http.StatusBadRequest, w.Code)

			var resp map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &resp)
			require.NoError(t, err)
			assert.Contains(t, resp["message"], "Limit must be between 1 and 10000")
		})
	}
}

// TestNewExportLogsHandler_ServiceError tests service error handling
func TestNewExportLogsHandler_ServiceError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockLogRepo := new(MockLogRepository)
	logService := service.NewLogService(mockLogRepo)

	mockLogRepo.On("FindPaginated", mock.Anything, 0, 1000).
		Return([]models.Log{}, int64(0), fmt.Errorf("database error"))

	handler := internalapi.NewExportLogsHandler(logService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/export/logs?format=json", nil)

	handler(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["message"], "Failed to fetch logs")

	mockLogRepo.AssertExpectations(t)
}

// TestNewExportLogsHandler_CustomLimit tests custom limit parameter
func TestNewExportLogsHandler_CustomLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockLogRepo := new(MockLogRepository)
	logService := service.NewLogService(mockLogRepo)

	mockLogRepo.On("FindPaginated", mock.Anything, 0, 500).
		Return([]models.Log{}, int64(0), nil)

	handler := internalapi.NewExportLogsHandler(logService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/export/logs?format=json&limit=500", nil)

	handler(c)

	assert.Equal(t, http.StatusOK, w.Code)

	mockLogRepo.AssertExpectations(t)
}

// TestNewExportAuditLogsHandler_JSON tests successful JSON export
func TestNewExportAuditLogsHandler_JSON(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockAuditLogRepo := new(MockAuditLogRepository)
	auditLogService := service.NewAuditLogService(mockAuditLogRepo)

	expectedLogs := []models.AuditLog{
		{
			ID:           1,
			UserID:       1,
			UserEmail:    "admin@example.com",
			Action:       "LOGIN",
			ResourceType: "user",
			ResourceID:   "1",
			Details:      "Successful login",
			Status:       "success",
			IPAddress:    "1.2.3.4",
			CreatedAt:    time.Now(),
		},
	}

	mockAuditLogRepo.On("FindPaginated", mock.Anything, 0, 1000).
		Return(expectedLogs, int64(1), nil)

	handler := internalapi.NewExportAuditLogsHandler(auditLogService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/export/audit-logs?format=json", nil)

	handler(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")
	assert.Contains(t, w.Header().Get("Content-Disposition"), "audit_logs_")

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, float64(1), resp["count"])

	mockAuditLogRepo.AssertExpectations(t)
}

// TestNewExportAuditLogsHandler_CSV tests successful CSV export
func TestNewExportAuditLogsHandler_CSV(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockAuditLogRepo := new(MockAuditLogRepository)
	auditLogService := service.NewAuditLogService(mockAuditLogRepo)

	expectedLogs := []models.AuditLog{
		{
			ID:           1,
			UserID:       1,
			UserEmail:    "admin@example.com",
			Action:       "LOGIN",
			ResourceType: "user",
			ResourceID:   "1",
			Details:      "Successful login",
			Status:       "success",
			IPAddress:    "1.2.3.4",
			CreatedAt:    time.Now(),
		},
	}

	mockAuditLogRepo.On("FindPaginated", mock.Anything, 0, 1000).
		Return(expectedLogs, int64(1), nil)

	handler := internalapi.NewExportAuditLogsHandler(auditLogService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/export/audit-logs?format=csv", nil)

	handler(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/csv")

	reader := csv.NewReader(strings.NewReader(w.Body.String()))
	records, err := reader.ReadAll()
	require.NoError(t, err)
	assert.Greater(t, len(records), 0)

	mockAuditLogRepo.AssertExpectations(t)
}

// TestNewExportAuditLogsHandler_XML tests successful XML export
func TestNewExportAuditLogsHandler_XML(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockAuditLogRepo := new(MockAuditLogRepository)
	auditLogService := service.NewAuditLogService(mockAuditLogRepo)

	expectedLogs := []models.AuditLog{
		{
			ID:           1,
			UserID:       1,
			UserEmail:    "admin@example.com",
			Action:       "LOGIN",
			ResourceType: "user",
			ResourceID:   "1",
			Details:      "Successful login",
			Status:       "success",
			IPAddress:    "1.2.3.4",
			CreatedAt:    time.Now(),
		},
	}

	mockAuditLogRepo.On("FindPaginated", mock.Anything, 0, 1000).
		Return(expectedLogs, int64(1), nil)

	handler := internalapi.NewExportAuditLogsHandler(auditLogService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/export/audit-logs?format=xml", nil)

	handler(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/xml")

	body := w.Body.String()
	assert.Contains(t, body, "<?xml version=")
	assert.Contains(t, body, "<audit_logs>")

	mockAuditLogRepo.AssertExpectations(t)
}

// TestNewExportAuditLogsHandler_InvalidFormat tests invalid format handling
func TestNewExportAuditLogsHandler_InvalidFormat(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockAuditLogRepo := new(MockAuditLogRepository)
	auditLogService := service.NewAuditLogService(mockAuditLogRepo)

	handler := internalapi.NewExportAuditLogsHandler(auditLogService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/export/audit-logs?format=yaml", nil)

	handler(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestNewExportAuditLogsHandler_ServiceError tests service error handling
func TestNewExportAuditLogsHandler_ServiceError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockAuditLogRepo := new(MockAuditLogRepository)
	auditLogService := service.NewAuditLogService(mockAuditLogRepo)

	mockAuditLogRepo.On("FindPaginated", mock.Anything, 0, 1000).
		Return([]models.AuditLog{}, int64(0), fmt.Errorf("database error"))

	handler := internalapi.NewExportAuditLogsHandler(auditLogService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/export/audit-logs?format=json", nil)

	handler(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["message"], "Failed to fetch audit logs")

	mockAuditLogRepo.AssertExpectations(t)
}

// TestNewExportBlocklistHandler_JSON tests successful JSON export
func TestNewExportBlocklistHandler_JSON(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockBlocklistRepo := new(MockBlocklistRepository)
	mockLogRepo := new(MockLogRepository)
	blocklistService := service.NewBlocklistService(mockBlocklistRepo, mockLogRepo)

	expectedIPs := []models.BlockedIP{
		{
			ID:          1,
			IPAddress:   "1.2.3.4",
			Description: "XSS",
			Reason:      "Attack detected",
			Permanent:   true,
			CreatedAt:   time.Now(),
		},
	}

	mockBlocklistRepo.On("FindActive", mock.Anything).
		Return(expectedIPs, nil)

	handler := internalapi.NewExportBlocklistHandler(blocklistService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/export/blocklist?format=json", nil)

	handler(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")
	assert.Contains(t, w.Header().Get("Content-Disposition"), "blocklist_")

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, float64(1), resp["count"])

	mockBlocklistRepo.AssertExpectations(t)
}

// TestNewExportBlocklistHandler_CSV tests successful CSV export
func TestNewExportBlocklistHandler_CSV(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockBlocklistRepo := new(MockBlocklistRepository)
	mockLogRepo := new(MockLogRepository)
	blocklistService := service.NewBlocklistService(mockBlocklistRepo, mockLogRepo)

	expectedIPs := []models.BlockedIP{
		{
			ID:          1,
			IPAddress:   "1.2.3.4",
			Description: "XSS",
			Reason:      "Attack detected",
			Permanent:   true,
			CreatedAt:   time.Now(),
		},
	}

	mockBlocklistRepo.On("FindActive", mock.Anything).
		Return(expectedIPs, nil)

	handler := internalapi.NewExportBlocklistHandler(blocklistService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/export/blocklist?format=csv", nil)

	handler(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/csv")

	reader := csv.NewReader(strings.NewReader(w.Body.String()))
	records, err := reader.ReadAll()
	require.NoError(t, err)
	assert.Greater(t, len(records), 0)

	mockBlocklistRepo.AssertExpectations(t)
}

// TestNewExportBlocklistHandler_XML tests successful XML export
func TestNewExportBlocklistHandler_XML(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockBlocklistRepo := new(MockBlocklistRepository)
	mockLogRepo := new(MockLogRepository)
	blocklistService := service.NewBlocklistService(mockBlocklistRepo, mockLogRepo)

	expectedIPs := []models.BlockedIP{
		{
			ID:          1,
			IPAddress:   "1.2.3.4",
			Description: "XSS",
			Reason:      "Attack detected",
			Permanent:   true,
			CreatedAt:   time.Now(),
		},
	}

	mockBlocklistRepo.On("FindActive", mock.Anything).
		Return(expectedIPs, nil)

	handler := internalapi.NewExportBlocklistHandler(blocklistService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/export/blocklist?format=xml", nil)

	handler(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/xml")

	body := w.Body.String()
	assert.Contains(t, body, "<?xml version=")
	assert.Contains(t, body, "<blocked_ips>")

	mockBlocklistRepo.AssertExpectations(t)
}

// TestNewExportBlocklistHandler_InvalidFormat tests invalid format handling
func TestNewExportBlocklistHandler_InvalidFormat(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockBlocklistRepo := new(MockBlocklistRepository)
	mockLogRepo := new(MockLogRepository)
	blocklistService := service.NewBlocklistService(mockBlocklistRepo, mockLogRepo)

	handler := internalapi.NewExportBlocklistHandler(blocklistService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/export/blocklist?format=txt", nil)

	handler(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestNewExportBlocklistHandler_ServiceError tests service error handling
func TestNewExportBlocklistHandler_ServiceError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockBlocklistRepo := new(MockBlocklistRepository)
	mockLogRepo := new(MockLogRepository)
	blocklistService := service.NewBlocklistService(mockBlocklistRepo, mockLogRepo)

	mockBlocklistRepo.On("FindActive", mock.Anything).
		Return([]models.BlockedIP{}, fmt.Errorf("database error"))

	handler := internalapi.NewExportBlocklistHandler(blocklistService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/export/blocklist?format=json", nil)

	handler(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["message"], "Failed to fetch blocked IPs")

	mockBlocklistRepo.AssertExpectations(t)
}

// TestExportLogsEmptyData tests export with empty data
func TestExportLogsEmptyData(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockLogRepo := new(MockLogRepository)
	logService := service.NewLogService(mockLogRepo)

	mockLogRepo.On("FindPaginated", mock.Anything, 0, 1000).
		Return([]models.Log{}, int64(0), nil)

	handler := internalapi.NewExportLogsHandler(logService)

	tests := []struct {
		name   string
		format string
	}{
		{"JSON empty", "json"},
		{"CSV empty", "csv"},
		{"XML empty", "xml"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("GET", fmt.Sprintf("/export/logs?format=%s", tt.format), nil)

			handler(c)

			assert.Equal(t, http.StatusOK, w.Code)
		})
	}

	mockLogRepo.AssertExpectations(t)
}
