package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/api"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// TestNewGetWhitelistHandler_Success tests successful whitelist retrieval with pagination
func TestNewGetWhitelistHandler_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockWhitelistRepo := new(MockWhitelistRepository)
	whitelistService := service.NewWhitelistService(mockWhitelistRepo)

	// Mock data
	expectedWhitelist := []models.WhitelistedIP{
		{
			ID:        1,
			IPAddress: "192.168.1.100",
			Reason:    "Trusted server",
			CreatedAt: time.Now(),
		},
		{
			ID:        2,
			IPAddress: "10.0.0.1",
			Reason:    "Internal network",
			CreatedAt: time.Now(),
		},
	}

	// Mock repository call
	mockWhitelistRepo.On("FindPaginated", mock.Anything, 0, 20).
		Return(expectedWhitelist, int64(2), nil).Once()

	handler := api.NewGetWhitelistHandler(whitelistService)

	// Create test request
	req, _ := http.NewRequest("GET", "/api/whitelist?limit=20&offset=0", nil)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert response
	assert.Equal(t, 200, w.Code)
	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.NotNil(t, response["items"])

	// Check pagination object
	pagination, ok := response["pagination"].(map[string]interface{})
	assert.True(t, ok, "Pagination should be present")
	assert.Equal(t, float64(2), pagination["total"])

	// Verify mock expectations
	mockWhitelistRepo.AssertExpectations(t)
}

// TestNewGetWhitelistHandler_InvalidPagination tests with invalid pagination parameters
func TestNewGetWhitelistHandler_InvalidPagination(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockWhitelistRepo := new(MockWhitelistRepository)
	whitelistService := service.NewWhitelistService(mockWhitelistRepo)

	handler := api.NewGetWhitelistHandler(whitelistService)

	// Create test request with invalid limit
	req, _ := http.NewRequest("GET", "/api/whitelist?limit=invalid", nil)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert error response
	assert.Equal(t, 400, w.Code)
	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "INVALID_REQUEST", response["code"])

	// Verify no service calls were made
	mockWhitelistRepo.AssertNotCalled(t, "FindPaginated")
}

// TestNewGetWhitelistHandler_ServiceError tests service error handling
func TestNewGetWhitelistHandler_ServiceError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockWhitelistRepo := new(MockWhitelistRepository)
	whitelistService := service.NewWhitelistService(mockWhitelistRepo)

	// Mock repository to return error
	mockWhitelistRepo.On("FindPaginated", mock.Anything, 0, 20).
		Return([]models.WhitelistedIP{}, int64(0), errors.New("database error")).Once()

	handler := api.NewGetWhitelistHandler(whitelistService)

	// Create test request
	req, _ := http.NewRequest("GET", "/api/whitelist?limit=20&offset=0", nil)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert error response
	assert.Equal(t, 500, w.Code)
	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "SERVICE_ERROR", response["code"])

	// Verify mock expectations
	mockWhitelistRepo.AssertExpectations(t)
}

// TestNewAddToWhitelistHandler_CreateNew tests creating a new whitelist entry
func TestNewAddToWhitelistHandler_CreateNew(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockWhitelistRepo := new(MockWhitelistRepository)
	whitelistService := service.NewWhitelistService(mockWhitelistRepo)

	// Mock check for existing IP (returns nil, meaning IP doesn't exist)
	mockWhitelistRepo.On("ExistsSoftDeleted", mock.Anything, "192.168.1.100").
		Return((*models.WhitelistedIP)(nil), nil).Once()

	// Mock create call
	mockWhitelistRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.WhitelistedIP")).
		Run(func(args mock.Arguments) {
			whitelist := args.Get(1).(*models.WhitelistedIP)
			assert.Equal(t, "192.168.1.100", whitelist.IPAddress)
			assert.Equal(t, "Test reason", whitelist.Reason)
		}).Return(nil).Once()

	handler := api.NewAddToWhitelistHandler(whitelistService)

	// Create test request
	reqBody := map[string]interface{}{
		"ip_address": "192.168.1.100",
		"reason":     "Test reason",
	}
	jsonData, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", "/api/whitelist", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert response
	assert.Equal(t, 201, w.Code)
	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "IP whitelisted successfully", response["message"])

	// Verify mock expectations
	mockWhitelistRepo.AssertExpectations(t)
}

// TestNewAddToWhitelistHandler_UpdateExisting tests updating an existing whitelist entry
func TestNewAddToWhitelistHandler_UpdateExisting(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockWhitelistRepo := new(MockWhitelistRepository)
	whitelistService := service.NewWhitelistService(mockWhitelistRepo)

	// Mock existing IP
	existingIP := &models.WhitelistedIP{
		ID:        1,
		IPAddress: "192.168.1.100",
		Reason:    "Old reason",
	}

	// Mock check for existing IP (returns existing IP)
	mockWhitelistRepo.On("ExistsSoftDeleted", mock.Anything, "192.168.1.100").
		Return(existingIP, nil).Once()

	// Mock update call
	mockWhitelistRepo.On("Update", mock.Anything, mock.AnythingOfType("*models.WhitelistedIP")).
		Run(func(args mock.Arguments) {
			whitelist := args.Get(1).(*models.WhitelistedIP)
			assert.Equal(t, "192.168.1.100", whitelist.IPAddress)
			assert.Equal(t, "Updated reason", whitelist.Reason)
		}).Return(nil).Once()

	handler := api.NewAddToWhitelistHandler(whitelistService)

	// Create test request
	reqBody := map[string]interface{}{
		"ip_address": "192.168.1.100",
		"reason":     "Updated reason",
	}
	jsonData, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", "/api/whitelist", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert response
	assert.Equal(t, 200, w.Code)
	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "Whitelist entry updated (IP already existed)", response["message"])

	// Verify mock expectations
	mockWhitelistRepo.AssertExpectations(t)
}

// TestNewAddToWhitelistHandler_InvalidJSON tests with malformed JSON
func TestNewAddToWhitelistHandler_InvalidJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockWhitelistRepo := new(MockWhitelistRepository)
	whitelistService := service.NewWhitelistService(mockWhitelistRepo)

	handler := api.NewAddToWhitelistHandler(whitelistService)

	// Create test request with invalid JSON
	req, _ := http.NewRequest("POST", "/api/whitelist", bytes.NewBufferString("{invalid json"))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert error response
	assert.Equal(t, 400, w.Code)
	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Contains(t, response["code"], "INVALID_JSON")

	// Verify no service calls were made
	mockWhitelistRepo.AssertNotCalled(t, "FindByIP")
	mockWhitelistRepo.AssertNotCalled(t, "Create")
}

// TestNewAddToWhitelistHandler_MissingIPAddress tests with missing IP address
func TestNewAddToWhitelistHandler_MissingIPAddress(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockWhitelistRepo := new(MockWhitelistRepository)
	whitelistService := service.NewWhitelistService(mockWhitelistRepo)

	handler := api.NewAddToWhitelistHandler(whitelistService)

	// Create test request without IP address
	reqBody := map[string]interface{}{
		"reason": "Test reason",
	}
	jsonData, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", "/api/whitelist", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert error response
	assert.Equal(t, 400, w.Code)
	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Contains(t, response["code"], "INVALID_JSON")

	// Verify no service calls were made
	mockWhitelistRepo.AssertNotCalled(t, "FindByIP")
	mockWhitelistRepo.AssertNotCalled(t, "Create")
}

// TestNewAddToWhitelistHandler_InvalidIP tests with invalid IP address
func TestNewAddToWhitelistHandler_InvalidIP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockWhitelistRepo := new(MockWhitelistRepository)
	whitelistService := service.NewWhitelistService(mockWhitelistRepo)

	handler := api.NewAddToWhitelistHandler(whitelistService)

	// Create test request with invalid IP
	reqBody := map[string]interface{}{
		"ip_address": "invalid-ip",
		"reason":     "Test reason",
	}
	jsonData, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", "/api/whitelist", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert error response
	assert.Equal(t, 400, w.Code)
	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "INVALID_IP", response["code"])

	// Verify no service calls were made
	mockWhitelistRepo.AssertNotCalled(t, "FindByIP")
	mockWhitelistRepo.AssertNotCalled(t, "Create")
}

// TestNewAddToWhitelistHandler_InvalidReason tests with invalid reason (empty or too long)
func TestNewAddToWhitelistHandler_InvalidReason(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockWhitelistRepo := new(MockWhitelistRepository)
	whitelistService := service.NewWhitelistService(mockWhitelistRepo)

	handler := api.NewAddToWhitelistHandler(whitelistService)

	// Create test request with reason too long (>500 chars)
	longReason := make([]byte, 501)
	for i := range longReason {
		longReason[i] = 'a'
	}

	reqBody := map[string]interface{}{
		"ip_address": "192.168.1.100",
		"reason":     string(longReason),
	}
	jsonData, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", "/api/whitelist", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert error response
	assert.Equal(t, 400, w.Code)
	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "INVALID_REQUEST", response["code"])

	// Verify no service calls were made
	mockWhitelistRepo.AssertNotCalled(t, "FindByIP")
	mockWhitelistRepo.AssertNotCalled(t, "Create")
}

// TestNewAddToWhitelistHandler_CreateError tests database error during create
func TestNewAddToWhitelistHandler_CreateError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockWhitelistRepo := new(MockWhitelistRepository)
	whitelistService := service.NewWhitelistService(mockWhitelistRepo)

	// Mock check for existing IP (returns nil)
	mockWhitelistRepo.On("ExistsSoftDeleted", mock.Anything, "192.168.1.100").
		Return((*models.WhitelistedIP)(nil), nil).Once()

	// Mock create call to return error
	mockWhitelistRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.WhitelistedIP")).
		Return(errors.New("database error")).Once()

	handler := api.NewAddToWhitelistHandler(whitelistService)

	// Create test request
	reqBody := map[string]interface{}{
		"ip_address": "192.168.1.100",
		"reason":     "Test reason",
	}
	jsonData, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", "/api/whitelist", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert error response
	assert.Equal(t, 500, w.Code)
	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "DATABASE_ERROR", response["code"])

	// Verify mock expectations
	mockWhitelistRepo.AssertExpectations(t)
}

// TestNewAddToWhitelistHandler_UpdateError tests database error during update
func TestNewAddToWhitelistHandler_UpdateError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockWhitelistRepo := new(MockWhitelistRepository)
	whitelistService := service.NewWhitelistService(mockWhitelistRepo)

	// Mock existing IP
	existingIP := &models.WhitelistedIP{
		ID:        1,
		IPAddress: "192.168.1.100",
		Reason:    "Old reason",
	}

	// Mock check for existing IP
	mockWhitelistRepo.On("ExistsSoftDeleted", mock.Anything, "192.168.1.100").
		Return(existingIP, nil).Once()

	// Mock update call to return error
	mockWhitelistRepo.On("Update", mock.Anything, mock.AnythingOfType("*models.WhitelistedIP")).
		Return(errors.New("database error")).Once()

	handler := api.NewAddToWhitelistHandler(whitelistService)

	// Create test request
	reqBody := map[string]interface{}{
		"ip_address": "192.168.1.100",
		"reason":     "Updated reason",
	}
	jsonData, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", "/api/whitelist", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert error response
	assert.Equal(t, 500, w.Code)
	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "DATABASE_ERROR", response["code"])

	// Verify mock expectations
	mockWhitelistRepo.AssertExpectations(t)
}

// TestNewRemoveFromWhitelistHandler_Success tests successful removal from whitelist
func TestNewRemoveFromWhitelistHandler_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockWhitelistRepo := new(MockWhitelistRepository)
	whitelistService := service.NewWhitelistService(mockWhitelistRepo)

	// Mock delete call
	mockWhitelistRepo.On("Delete", mock.Anything, uint(1)).Return(nil).Once()

	handler := api.NewRemoveFromWhitelistHandler(whitelistService)

	// Create test request
	req, _ := http.NewRequest("DELETE", "/api/whitelist/1", nil)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = gin.Params{{Key: "id", Value: "1"}}

	// Execute handler
	handler(c)

	// Assert response
	assert.Equal(t, 200, w.Code)
	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "IP removed from whitelist successfully", response["message"])

	// Verify mock expectations
	mockWhitelistRepo.AssertExpectations(t)
}

// TestNewRemoveFromWhitelistHandler_InvalidID tests with invalid ID
func TestNewRemoveFromWhitelistHandler_InvalidID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockWhitelistRepo := new(MockWhitelistRepository)
	whitelistService := service.NewWhitelistService(mockWhitelistRepo)

	handler := api.NewRemoveFromWhitelistHandler(whitelistService)

	// Create test request with invalid ID
	req, _ := http.NewRequest("DELETE", "/api/whitelist/invalid", nil)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = gin.Params{{Key: "id", Value: "invalid"}}

	// Execute handler
	handler(c)

	// Assert error response
	assert.Equal(t, 400, w.Code)
	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "INVALID_REQUEST", response["code"])

	// Verify no service calls were made
	mockWhitelistRepo.AssertNotCalled(t, "Delete")
}

// TestNewRemoveFromWhitelistHandler_ServiceError tests database error during removal
func TestNewRemoveFromWhitelistHandler_ServiceError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockWhitelistRepo := new(MockWhitelistRepository)
	whitelistService := service.NewWhitelistService(mockWhitelistRepo)

	// Mock delete call to return error
	mockWhitelistRepo.On("Delete", mock.Anything, uint(1)).Return(errors.New("database error")).Once()

	handler := api.NewRemoveFromWhitelistHandler(whitelistService)

	// Create test request
	req, _ := http.NewRequest("DELETE", "/api/whitelist/1", nil)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = gin.Params{{Key: "id", Value: "1"}}

	// Execute handler
	handler(c)

	// Assert error response
	assert.Equal(t, 500, w.Code)
	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "DATABASE_ERROR", response["code"])

	// Verify mock expectations
	mockWhitelistRepo.AssertExpectations(t)
}

// TestNewGetWhitelistForWAFHandler_Success tests successful WAF whitelist retrieval
func TestNewGetWhitelistForWAFHandler_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockWhitelistRepo := new(MockWhitelistRepository)
	whitelistService := service.NewWhitelistService(mockWhitelistRepo)

	// Mock data
	expectedWhitelist := []models.WhitelistedIP{
		{
			ID:        1,
			IPAddress: "192.168.1.100",
			Reason:    "Trusted server",
		},
		{
			ID:        2,
			IPAddress: "10.0.0.1",
			Reason:    "Internal network",
		},
		{
			ID:        3,
			IPAddress: "172.16.0.1",
			Reason:    "Test server",
		},
	}

	// Mock repository call
	mockWhitelistRepo.On("FindAll", mock.Anything).
		Return(expectedWhitelist, nil).Once()

	handler := api.NewGetWhitelistForWAFHandler(whitelistService)

	// Create test request
	req, _ := http.NewRequest("GET", "/api/waf/whitelist", nil)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert response
	assert.Equal(t, 200, w.Code)
	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)

	// Verify response structure
	assert.NotNil(t, response["items"])
	assert.Equal(t, float64(3), response["count"])

	// Verify whitelist map contains expected IPs
	items, ok := response["items"].(map[string]interface{})
	assert.True(t, ok, "Items should be a map")
	assert.Equal(t, true, items["192.168.1.100"])
	assert.Equal(t, true, items["10.0.0.1"])
	assert.Equal(t, true, items["172.16.0.1"])

	// Verify mock expectations
	mockWhitelistRepo.AssertExpectations(t)
}

// TestNewGetWhitelistForWAFHandler_EmptyWhitelist tests with empty whitelist
func TestNewGetWhitelistForWAFHandler_EmptyWhitelist(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockWhitelistRepo := new(MockWhitelistRepository)
	whitelistService := service.NewWhitelistService(mockWhitelistRepo)

	// Mock repository call with empty result
	mockWhitelistRepo.On("FindAll", mock.Anything).
		Return([]models.WhitelistedIP{}, nil).Once()

	handler := api.NewGetWhitelistForWAFHandler(whitelistService)

	// Create test request
	req, _ := http.NewRequest("GET", "/api/waf/whitelist", nil)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert response
	assert.Equal(t, 200, w.Code)
	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)

	// Verify empty response
	assert.NotNil(t, response["items"])
	assert.Equal(t, float64(0), response["count"])

	// Verify mock expectations
	mockWhitelistRepo.AssertExpectations(t)
}

// TestNewGetWhitelistForWAFHandler_ServiceError tests service error handling
func TestNewGetWhitelistForWAFHandler_ServiceError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockWhitelistRepo := new(MockWhitelistRepository)
	whitelistService := service.NewWhitelistService(mockWhitelistRepo)

	// Mock repository to return error
	mockWhitelistRepo.On("FindAll", mock.Anything).
		Return([]models.WhitelistedIP{}, errors.New("database error")).Once()

	handler := api.NewGetWhitelistForWAFHandler(whitelistService)

	// Create test request
	req, _ := http.NewRequest("GET", "/api/waf/whitelist", nil)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert error response
	assert.Equal(t, 500, w.Code)
	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "SERVICE_ERROR", response["code"])

	// Verify mock expectations
	mockWhitelistRepo.AssertExpectations(t)
}
