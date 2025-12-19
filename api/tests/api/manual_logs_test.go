package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/api"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"gorm.io/gorm"
)

// TestNewLogManualBlockHandler_Success tests successful manual block logging
func TestNewLogManualBlockHandler_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockLogRepo := new(MockLogRepository)
	mockDB := &gorm.DB{}

	// Set up mock expectation
	mockLogRepo.On("Create", mock.Anything, mock.MatchedBy(func(log *models.Log) bool {
		return log.ThreatType == "XSS" &&
			log.Severity == "high" &&
			log.ClientIP == "192.168.1.100" &&
			log.Method == "MANUAL_BLOCK" &&
			log.Blocked == true &&
			log.BlockedBy == "manual" &&
			log.Description == "Suspicious XSS attempt" &&
			log.URL == "/test" &&
			log.UserAgent == "TestAgent" &&
			log.Payload == "<script>alert('test')</script>"
	})).Return(nil).Once()

	// Create service and handler
	logService := service.NewLogService(mockLogRepo)
	handler := api.NewLogManualBlockHandler(logService, mockDB)

	// Create test request
	reqBody := map[string]interface{}{
		"ip":          "192.168.1.100",
		"threat_type": "XSS",
		"severity":    "high",
		"description": "Suspicious XSS attempt",
		"url":         "/test",
		"user_agent":  "TestAgent",
		"payload":     "<script>alert('test')</script>",
	}
	jsonData, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", "/api/logs/manual-block", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert response
	assert.Equal(t, 201, w.Code)
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "Manual block logged successfully", resp["message"])

	// Verify mock expectations
	mockLogRepo.AssertExpectations(t)
}

// TestNewLogManualBlockHandler_MinimalFields tests with only required fields
func TestNewLogManualBlockHandler_MinimalFields(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockLogRepo := new(MockLogRepository)
	mockDB := &gorm.DB{}

	// Set up mock expectation
	mockLogRepo.On("Create", mock.Anything, mock.MatchedBy(func(log *models.Log) bool {
		return log.ThreatType == "SQL_INJECTION" &&
			log.ClientIP == "10.0.0.1" &&
			log.Method == "MANUAL_BLOCK" &&
			log.Blocked == true &&
			log.BlockedBy == "manual" &&
			log.Severity == "" && // Optional field not provided
			log.Description == "" &&
			log.URL == "" &&
			log.UserAgent == "" &&
			log.Payload == ""
	})).Return(nil).Once()

	// Create service and handler
	logService := service.NewLogService(mockLogRepo)
	handler := api.NewLogManualBlockHandler(logService, mockDB)

	// Create test request with only required fields
	reqBody := map[string]interface{}{
		"ip":          "10.0.0.1",
		"threat_type": "SQL_INJECTION",
	}
	jsonData, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", "/api/logs/manual-block", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert response
	assert.Equal(t, 201, w.Code)
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "Manual block logged successfully", resp["message"])

	// Verify mock expectations
	mockLogRepo.AssertExpectations(t)
}

// TestNewLogManualBlockHandler_InvalidJSON tests with malformed JSON
func TestNewLogManualBlockHandler_InvalidJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockLogRepo := new(MockLogRepository)
	mockDB := &gorm.DB{}

	// Create service and handler
	logService := service.NewLogService(mockLogRepo)
	handler := api.NewLogManualBlockHandler(logService, mockDB)

	// Create test request with invalid JSON
	req, _ := http.NewRequest("POST", "/api/logs/manual-block", bytes.NewBufferString("{invalid json"))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert error response
	assert.Equal(t, 400, w.Code)
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Contains(t, resp["code"], "INVALID_JSON")

	// Verify no service calls were made
	mockLogRepo.AssertNotCalled(t, "Create")
}

// TestNewLogManualBlockHandler_MissingIP tests with missing required IP field
func TestNewLogManualBlockHandler_MissingIP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockLogRepo := new(MockLogRepository)
	mockDB := &gorm.DB{}

	// Create service and handler
	logService := service.NewLogService(mockLogRepo)
	handler := api.NewLogManualBlockHandler(logService, mockDB)

	// Create test request without IP field
	reqBody := map[string]interface{}{
		"threat_type": "XSS",
		"severity":    "high",
	}
	jsonData, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", "/api/logs/manual-block", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert error response
	assert.Equal(t, 400, w.Code)
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Contains(t, resp["code"], "INVALID_JSON")

	// Verify no service calls were made
	mockLogRepo.AssertNotCalled(t, "Create")
}

// TestNewLogManualBlockHandler_MissingThreatType tests with missing required threat_type field
func TestNewLogManualBlockHandler_MissingThreatType(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockLogRepo := new(MockLogRepository)
	mockDB := &gorm.DB{}

	// Create service and handler
	logService := service.NewLogService(mockLogRepo)
	handler := api.NewLogManualBlockHandler(logService, mockDB)

	// Create test request without threat_type field
	reqBody := map[string]interface{}{
		"ip":       "192.168.1.100",
		"severity": "high",
	}
	jsonData, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", "/api/logs/manual-block", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert error response
	assert.Equal(t, 400, w.Code)
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Contains(t, resp["code"], "INVALID_JSON")

	// Verify no service calls were made
	mockLogRepo.AssertNotCalled(t, "Create")
}

// TestNewLogManualBlockHandler_ServiceError tests database error handling
func TestNewLogManualBlockHandler_ServiceError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockLogRepo := new(MockLogRepository)
	mockDB := &gorm.DB{}

	// Set up mock to return error
	mockLogRepo.On("Create", mock.Anything, mock.Anything).Return(errors.New("database connection error")).Once()

	// Create service and handler
	logService := service.NewLogService(mockLogRepo)
	handler := api.NewLogManualBlockHandler(logService, mockDB)

	// Create test request
	reqBody := map[string]interface{}{
		"ip":          "192.168.1.100",
		"threat_type": "XSS",
		"severity":    "high",
	}
	jsonData, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", "/api/logs/manual-block", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert error response
	assert.Equal(t, 500, w.Code)
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "DATABASE_ERROR", resp["code"])
	assert.Equal(t, "Failed to log event", resp["message"])

	// Verify mock expectations
	mockLogRepo.AssertExpectations(t)
}

// TestNewLogManualUnblockHandler_Success tests successful manual unblock processing
func TestNewLogManualUnblockHandler_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create handler
	handler := api.NewLogManualUnblockHandler()

	// Create test request
	reqBody := map[string]interface{}{
		"ip":          "192.168.1.100",
		"threat_type": "XSS",
		"severity":    "high",
		"description": "Unblocking XSS rule",
		"url":         "/test",
		"user_agent":  "TestAgent",
		"payload":     "<script>alert('test')</script>",
	}
	jsonData, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", "/api/logs/manual-unblock", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert response
	assert.Equal(t, 201, w.Code)
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "Manual unblock processed successfully", resp["message"])
}

// TestNewLogManualUnblockHandler_MinimalFields tests with only required fields
func TestNewLogManualUnblockHandler_MinimalFields(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create handler
	handler := api.NewLogManualUnblockHandler()

	// Create test request with only required fields
	reqBody := map[string]interface{}{
		"ip":          "10.0.0.1",
		"threat_type": "SQL_INJECTION",
	}
	jsonData, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", "/api/logs/manual-unblock", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert response
	assert.Equal(t, 201, w.Code)
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "Manual unblock processed successfully", resp["message"])
}

// TestNewLogManualUnblockHandler_InvalidJSON tests with malformed JSON
func TestNewLogManualUnblockHandler_InvalidJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create handler
	handler := api.NewLogManualUnblockHandler()

	// Create test request with invalid JSON
	req, _ := http.NewRequest("POST", "/api/logs/manual-unblock", bytes.NewBufferString("{invalid json"))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert error response
	assert.Equal(t, 400, w.Code)
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Contains(t, resp["code"], "INVALID_JSON")
}

// TestNewLogManualUnblockHandler_MissingIP tests with missing required IP field
func TestNewLogManualUnblockHandler_MissingIP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create handler
	handler := api.NewLogManualUnblockHandler()

	// Create test request without IP field
	reqBody := map[string]interface{}{
		"threat_type": "XSS",
		"severity":    "high",
	}
	jsonData, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", "/api/logs/manual-unblock", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert error response
	assert.Equal(t, 400, w.Code)
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Contains(t, resp["code"], "INVALID_JSON")
}

// TestNewLogManualUnblockHandler_MissingThreatType tests with missing required threat_type field
func TestNewLogManualUnblockHandler_MissingThreatType(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create handler
	handler := api.NewLogManualUnblockHandler()

	// Create test request without threat_type field
	reqBody := map[string]interface{}{
		"ip":       "192.168.1.100",
		"severity": "high",
	}
	jsonData, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", "/api/logs/manual-unblock", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert error response
	assert.Equal(t, 400, w.Code)
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Contains(t, resp["code"], "INVALID_JSON")
}
