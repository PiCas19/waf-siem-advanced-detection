package api

import (
	"bytes"
	"context"
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

// MockFalsePositiveRepository for testing false positive functionality
type MockFalsePositiveRepository struct {
	mock.Mock
}

func (m *MockFalsePositiveRepository) FindAll(ctx context.Context) ([]models.FalsePositive, error) {
	args := m.Called(ctx)
	return args.Get(0).([]models.FalsePositive), args.Error(1)
}

func (m *MockFalsePositiveRepository) FindByID(ctx context.Context, id uint) (*models.FalsePositive, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.FalsePositive), args.Error(1)
}

func (m *MockFalsePositiveRepository) Create(ctx context.Context, falsePositive *models.FalsePositive) error {
	args := m.Called(ctx, falsePositive)
	return args.Error(0)
}

func (m *MockFalsePositiveRepository) Update(ctx context.Context, falsePositive *models.FalsePositive) error {
	args := m.Called(ctx, falsePositive)
	return args.Error(0)
}

func (m *MockFalsePositiveRepository) Delete(ctx context.Context, id uint) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockFalsePositiveRepository) Count(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockFalsePositiveRepository) CountUnresolved(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockFalsePositiveRepository) FindPaginated(ctx context.Context, offset int, limit int) ([]models.FalsePositive, int64, error) {
	args := m.Called(ctx, offset, limit)
	return args.Get(0).([]models.FalsePositive), args.Get(1).(int64), args.Error(2)
}

func (m *MockFalsePositiveRepository) FindByIP(ctx context.Context, ip string) ([]models.FalsePositive, error) {
	args := m.Called(ctx, ip)
	return args.Get(0).([]models.FalsePositive), args.Error(1)
}

func (m *MockFalsePositiveRepository) FindUnresolved(ctx context.Context) ([]models.FalsePositive, error) {
	args := m.Called(ctx)
	return args.Get(0).([]models.FalsePositive), args.Error(1)
}

// TestNewGetFalsePositivesHandler_Success tests successful retrieval
func TestNewGetFalsePositivesHandler_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockFPRepo := new(MockFalsePositiveRepository)
	fpService := service.NewFalsePositiveService(mockFPRepo)

	expectedFPs := []models.FalsePositive{
		{
			ID:          1,
			ThreatType:  "XSS",
			Description: "Test false positive",
			ClientIP:    "1.2.3.4",
			Method:      "GET",
			URL:         "/test",
			Status:      "pending",
			CreatedAt:   time.Now(),
		},
	}

	mockFPRepo.On("FindPaginated", mock.Anything, 0, 20).
		Return(expectedFPs, int64(1), nil)

	handler := internalapi.NewGetFalsePositivesHandler(fpService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/false-positives", nil)

	handler(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, float64(1), resp["count"])

	mockFPRepo.AssertExpectations(t)
}

// TestNewGetFalsePositivesHandler_InvalidParams tests invalid pagination params
func TestNewGetFalsePositivesHandler_InvalidParams(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockFPRepo := new(MockFalsePositiveRepository)
	fpService := service.NewFalsePositiveService(mockFPRepo)

	handler := internalapi.NewGetFalsePositivesHandler(fpService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/false-positives?limit=invalid", nil)

	handler(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["code"], "INVALID_REQUEST")
}

// TestNewGetFalsePositivesHandler_ServiceError tests service error handling
func TestNewGetFalsePositivesHandler_ServiceError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockFPRepo := new(MockFalsePositiveRepository)
	fpService := service.NewFalsePositiveService(mockFPRepo)

	mockFPRepo.On("FindPaginated", mock.Anything, 0, 20).
		Return([]models.FalsePositive{}, int64(0), fmt.Errorf("database error"))

	handler := internalapi.NewGetFalsePositivesHandler(fpService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/false-positives", nil)

	handler(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["message"], "Failed to fetch false positives")

	mockFPRepo.AssertExpectations(t)
}

// TestNewReportFalsePositiveHandler_Success tests successful false positive report
func TestNewReportFalsePositiveHandler_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockFPRepo := new(MockFalsePositiveRepository)
	fpService := service.NewFalsePositiveService(mockFPRepo)

	mockFPRepo.On("Create", mock.Anything, mock.MatchedBy(func(fp *models.FalsePositive) bool {
		return fp.ThreatType == "XSS" &&
			fp.ClientIP == "1.2.3.4" &&
			fp.Status == "pending"
	})).Return(nil)

	handler := internalapi.NewReportFalsePositiveHandler(fpService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/false-positives", bytes.NewBufferString(`{
		"threat_type": "XSS",
		"description": "Test FP",
		"client_ip": "1.2.3.4",
		"method": "GET",
		"url": "http://example.com/test",
		"payload": "<script>alert('test')</script>",
		"user_agent": "Mozilla/5.0"
	}`))
	c.Request.Header.Set("Content-Type", "application/json")

	handler(c)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["message"], "False positive reported successfully")

	mockFPRepo.AssertExpectations(t)
}

// TestNewReportFalsePositiveHandler_InvalidJSON tests invalid JSON handling
func TestNewReportFalsePositiveHandler_InvalidJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockFPRepo := new(MockFalsePositiveRepository)
	fpService := service.NewFalsePositiveService(mockFPRepo)

	handler := internalapi.NewReportFalsePositiveHandler(fpService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/false-positives", bytes.NewBufferString(`{invalid json`))
	c.Request.Header.Set("Content-Type", "application/json")

	handler(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestNewReportFalsePositiveHandler_MissingThreatType tests missing threat type
func TestNewReportFalsePositiveHandler_MissingThreatType(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockFPRepo := new(MockFalsePositiveRepository)
	fpService := service.NewFalsePositiveService(mockFPRepo)

	handler := internalapi.NewReportFalsePositiveHandler(fpService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/false-positives", bytes.NewBufferString(`{
		"client_ip": "1.2.3.4"
	}`))
	c.Request.Header.Set("Content-Type", "application/json")

	handler(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestNewReportFalsePositiveHandler_InvalidIP tests invalid IP address
func TestNewReportFalsePositiveHandler_InvalidIP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockFPRepo := new(MockFalsePositiveRepository)
	fpService := service.NewFalsePositiveService(mockFPRepo)

	handler := internalapi.NewReportFalsePositiveHandler(fpService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/false-positives", bytes.NewBufferString(`{
		"threat_type": "XSS",
		"client_ip": "invalid_ip"
	}`))
	c.Request.Header.Set("Content-Type", "application/json")

	handler(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["code"], "INVALID_IP")
}

// TestNewReportFalsePositiveHandler_InvalidURL tests invalid URL
func TestNewReportFalsePositiveHandler_InvalidURL(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockFPRepo := new(MockFalsePositiveRepository)
	fpService := service.NewFalsePositiveService(mockFPRepo)

	handler := internalapi.NewReportFalsePositiveHandler(fpService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/false-positives", bytes.NewBufferString(`{
		"threat_type": "XSS",
		"client_ip": "1.2.3.4",
		"url": "not a valid url"
	}`))
	c.Request.Header.Set("Content-Type", "application/json")

	handler(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["message"], "Invalid URL")
}

// TestNewReportFalsePositiveHandler_InvalidMethod tests invalid HTTP method
func TestNewReportFalsePositiveHandler_InvalidMethod(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockFPRepo := new(MockFalsePositiveRepository)
	fpService := service.NewFalsePositiveService(mockFPRepo)

	handler := internalapi.NewReportFalsePositiveHandler(fpService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/false-positives", bytes.NewBufferString(`{
		"threat_type": "XSS",
		"client_ip": "1.2.3.4",
		"method": "INVALID"
	}`))
	c.Request.Header.Set("Content-Type", "application/json")

	handler(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["code"], "INVALID_REQUEST")
}

// TestNewReportFalsePositiveHandler_InvalidPayload tests invalid payload
func TestNewReportFalsePositiveHandler_InvalidPayload(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockFPRepo := new(MockFalsePositiveRepository)
	fpService := service.NewFalsePositiveService(mockFPRepo)

	handler := internalapi.NewReportFalsePositiveHandler(fpService)

	// Create a very long payload (> 10000 characters)
	longPayload := make([]byte, 11000)
	for i := range longPayload {
		longPayload[i] = 'a'
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/false-positives", bytes.NewBufferString(fmt.Sprintf(`{
		"threat_type": "XSS",
		"client_ip": "1.2.3.4",
		"payload": "%s"
	}`, string(longPayload))))
	c.Request.Header.Set("Content-Type", "application/json")

	handler(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestNewReportFalsePositiveHandler_InvalidUserAgent tests invalid user agent
func TestNewReportFalsePositiveHandler_InvalidUserAgent(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockFPRepo := new(MockFalsePositiveRepository)
	fpService := service.NewFalsePositiveService(mockFPRepo)

	handler := internalapi.NewReportFalsePositiveHandler(fpService)

	// Create a very long user agent (> 500 characters)
	longUserAgent := make([]byte, 600)
	for i := range longUserAgent {
		longUserAgent[i] = 'a'
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/false-positives", bytes.NewBufferString(fmt.Sprintf(`{
		"threat_type": "XSS",
		"client_ip": "1.2.3.4",
		"user_agent": "%s"
	}`, string(longUserAgent))))
	c.Request.Header.Set("Content-Type", "application/json")

	handler(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestNewReportFalsePositiveHandler_ServiceError tests service error handling
func TestNewReportFalsePositiveHandler_ServiceError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockFPRepo := new(MockFalsePositiveRepository)
	fpService := service.NewFalsePositiveService(mockFPRepo)

	mockFPRepo.On("Create", mock.Anything, mock.Anything).
		Return(fmt.Errorf("database error"))

	handler := internalapi.NewReportFalsePositiveHandler(fpService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/false-positives", bytes.NewBufferString(`{
		"threat_type": "XSS",
		"client_ip": "1.2.3.4"
	}`))
	c.Request.Header.Set("Content-Type", "application/json")

	handler(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["message"], "Failed to report false positive")

	mockFPRepo.AssertExpectations(t)
}

// TestNewUpdateFalsePositiveStatusHandler_Success tests successful status update
func TestNewUpdateFalsePositiveStatusHandler_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockFPRepo := new(MockFalsePositiveRepository)
	fpService := service.NewFalsePositiveService(mockFPRepo)

	mockFPRepo.On("Update", mock.Anything, mock.MatchedBy(func(fp *models.FalsePositive) bool {
		return fp.ID == 1 &&
			fp.Status == "reviewed" &&
			fp.ReviewNotes == "Looks good"
	})).Return(nil)

	handler := internalapi.NewUpdateFalsePositiveStatusHandler(fpService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "id", Value: "1"}}
	c.Request = httptest.NewRequest("PUT", "/false-positives/1", bytes.NewBufferString(`{
		"status": "reviewed",
		"review_notes": "Looks good"
	}`))
	c.Request.Header.Set("Content-Type", "application/json")

	handler(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["message"], "Status updated successfully")

	mockFPRepo.AssertExpectations(t)
}

// TestNewUpdateFalsePositiveStatusHandler_InvalidID tests invalid ID
func TestNewUpdateFalsePositiveStatusHandler_InvalidID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockFPRepo := new(MockFalsePositiveRepository)
	fpService := service.NewFalsePositiveService(mockFPRepo)

	handler := internalapi.NewUpdateFalsePositiveStatusHandler(fpService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "id", Value: "invalid"}}
	c.Request = httptest.NewRequest("PUT", "/false-positives/invalid", bytes.NewBufferString(`{
		"status": "approved"
	}`))
	c.Request.Header.Set("Content-Type", "application/json")

	handler(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["message"], "Invalid ID")
}

// TestNewUpdateFalsePositiveStatusHandler_InvalidJSON tests invalid JSON
func TestNewUpdateFalsePositiveStatusHandler_InvalidJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockFPRepo := new(MockFalsePositiveRepository)
	fpService := service.NewFalsePositiveService(mockFPRepo)

	handler := internalapi.NewUpdateFalsePositiveStatusHandler(fpService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "id", Value: "1"}}
	c.Request = httptest.NewRequest("PUT", "/false-positives/1", bytes.NewBufferString(`{invalid json`))
	c.Request.Header.Set("Content-Type", "application/json")

	handler(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestNewUpdateFalsePositiveStatusHandler_InvalidStatus tests invalid status
func TestNewUpdateFalsePositiveStatusHandler_InvalidStatus(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockFPRepo := new(MockFalsePositiveRepository)
	fpService := service.NewFalsePositiveService(mockFPRepo)

	handler := internalapi.NewUpdateFalsePositiveStatusHandler(fpService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "id", Value: "1"}}
	c.Request = httptest.NewRequest("PUT", "/false-positives/1", bytes.NewBufferString(`{
		"status": "invalid_status"
	}`))
	c.Request.Header.Set("Content-Type", "application/json")

	handler(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["code"], "INVALID_REQUEST")
}

// TestNewUpdateFalsePositiveStatusHandler_InvalidReviewNotes tests invalid review notes
func TestNewUpdateFalsePositiveStatusHandler_InvalidReviewNotes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockFPRepo := new(MockFalsePositiveRepository)
	fpService := service.NewFalsePositiveService(mockFPRepo)

	handler := internalapi.NewUpdateFalsePositiveStatusHandler(fpService)

	// Create very long review notes (> 1000 characters)
	longNotes := make([]byte, 1100)
	for i := range longNotes {
		longNotes[i] = 'a'
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "id", Value: "1"}}
	c.Request = httptest.NewRequest("PUT", "/false-positives/1", bytes.NewBufferString(fmt.Sprintf(`{
		"status": "approved",
		"review_notes": "%s"
	}`, string(longNotes))))
	c.Request.Header.Set("Content-Type", "application/json")

	handler(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["code"], "INVALID_REQUEST")
}

// TestNewUpdateFalsePositiveStatusHandler_ServiceError tests service error
func TestNewUpdateFalsePositiveStatusHandler_ServiceError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockFPRepo := new(MockFalsePositiveRepository)
	fpService := service.NewFalsePositiveService(mockFPRepo)

	mockFPRepo.On("Update", mock.Anything, mock.Anything).
		Return(fmt.Errorf("database error"))

	handler := internalapi.NewUpdateFalsePositiveStatusHandler(fpService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "id", Value: "1"}}
	c.Request = httptest.NewRequest("PUT", "/false-positives/1", bytes.NewBufferString(`{
		"status": "reviewed"
	}`))
	c.Request.Header.Set("Content-Type", "application/json")

	handler(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["message"], "Failed to update false positive")

	mockFPRepo.AssertExpectations(t)
}

// TestNewDeleteFalsePositiveHandler_Success tests successful deletion
func TestNewDeleteFalsePositiveHandler_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockFPRepo := new(MockFalsePositiveRepository)
	fpService := service.NewFalsePositiveService(mockFPRepo)

	mockFPRepo.On("Delete", mock.Anything, uint(1)).Return(nil)

	handler := internalapi.NewDeleteFalsePositiveHandler(fpService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "id", Value: "1"}}
	c.Request = httptest.NewRequest("DELETE", "/false-positives/1", nil)

	handler(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["message"], "Entry deleted successfully")

	mockFPRepo.AssertExpectations(t)
}

// TestNewDeleteFalsePositiveHandler_InvalidID tests invalid ID
func TestNewDeleteFalsePositiveHandler_InvalidID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockFPRepo := new(MockFalsePositiveRepository)
	fpService := service.NewFalsePositiveService(mockFPRepo)

	handler := internalapi.NewDeleteFalsePositiveHandler(fpService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "id", Value: "invalid"}}
	c.Request = httptest.NewRequest("DELETE", "/false-positives/invalid", nil)

	handler(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["message"], "Invalid ID")
}

// TestNewDeleteFalsePositiveHandler_ServiceError tests service error
func TestNewDeleteFalsePositiveHandler_ServiceError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockFPRepo := new(MockFalsePositiveRepository)
	fpService := service.NewFalsePositiveService(mockFPRepo)

	mockFPRepo.On("Delete", mock.Anything, uint(1)).
		Return(fmt.Errorf("database error"))

	handler := internalapi.NewDeleteFalsePositiveHandler(fpService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "id", Value: "1"}}
	c.Request = httptest.NewRequest("DELETE", "/false-positives/1", nil)

	handler(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["message"], "Failed to delete false positive")

	mockFPRepo.AssertExpectations(t)
}
