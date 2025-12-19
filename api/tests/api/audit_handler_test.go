package api

import (
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

	internalapi "github.com/PiCas19/waf-siem-advanced-detection/api/internal/api"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/service"
)

// MockAuditLogRepository is a mock implementation of AuditLogRepository
type MockAuditLogRepository struct {
	mock.Mock
}

func (m *MockAuditLogRepository) FindAll(ctx context.Context) ([]models.AuditLog, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.AuditLog), args.Error(1)
}

func (m *MockAuditLogRepository) FindByUser(ctx context.Context, userID uint) ([]models.AuditLog, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.AuditLog), args.Error(1)
}

func (m *MockAuditLogRepository) FindByAction(ctx context.Context, action string) ([]models.AuditLog, error) {
	args := m.Called(ctx, action)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.AuditLog), args.Error(1)
}

func (m *MockAuditLogRepository) FindRecent(ctx context.Context, limit int) ([]models.AuditLog, error) {
	args := m.Called(ctx, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]models.AuditLog), args.Error(1)
}

func (m *MockAuditLogRepository) FindPaginated(ctx context.Context, offset, limit int) ([]models.AuditLog, int64, error) {
	args := m.Called(ctx, offset, limit)
	if args.Get(0) == nil {
		return nil, 0, args.Error(2)
	}
	return args.Get(0).([]models.AuditLog), args.Get(1).(int64), args.Error(2)
}

func (m *MockAuditLogRepository) Count(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockAuditLogRepository) CountByStatus(ctx context.Context, status string) (int64, error) {
	args := m.Called(ctx, status)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockAuditLogRepository) GetActionBreakdown(ctx context.Context) (map[string]int64, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]int64), args.Error(1)
}

func (m *MockAuditLogRepository) Create(ctx context.Context, auditLog *models.AuditLog) error {
	args := m.Called(ctx, auditLog)
	return args.Error(0)
}

// TestNewGetAuditLogsHandler_Success tests successful audit logs retrieval with pagination
func TestNewGetAuditLogsHandler_Success(t *testing.T) {
	mockRepo := new(MockAuditLogRepository)
	auditLogs := []models.AuditLog{
		{
			ID:        1,
			UserID:    1,
			Action:    "user.login",
			Status:    "success",
			Details:   "User logged in",
			CreatedAt: time.Now(),
		},
		{
			ID:        2,
			UserID:    2,
			Action:    "rule.created",
			Status:    "success",
			Details:   "New rule created",
			CreatedAt: time.Now(),
		},
	}

	mockRepo.On("FindPaginated", mock.Anything, 0, 20).Return(auditLogs, int64(2), nil)

	auditLogService := service.NewAuditLogService(mockRepo)
	handler := internalapi.NewGetAuditLogsHandler(auditLogService)

	router := gin.New()
	router.GET("/audit-logs", handler)

	req, _ := http.NewRequest("GET", "/audit-logs", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)

	assert.NotNil(t, response["audit_logs"])
	assert.NotNil(t, response["pagination"])

	mockRepo.AssertExpectations(t)
}

// TestNewGetAuditLogsHandler_WithCustomLimit tests audit logs with custom limit
func TestNewGetAuditLogsHandler_WithCustomLimit(t *testing.T) {
	mockRepo := new(MockAuditLogRepository)
	auditLogs := []models.AuditLog{
		{
			ID:        1,
			UserID:    1,
			Action:    "user.login",
			Status:    "success",
			CreatedAt: time.Now(),
		},
	}

	mockRepo.On("FindPaginated", mock.Anything, 0, 50).Return(auditLogs, int64(1), nil)

	auditLogService := service.NewAuditLogService(mockRepo)
	handler := internalapi.NewGetAuditLogsHandler(auditLogService)

	router := gin.New()
	router.GET("/audit-logs", handler)

	req, _ := http.NewRequest("GET", "/audit-logs?limit=50&offset=0", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	mockRepo.AssertExpectations(t)
}

// TestNewGetAuditLogsHandler_WithOffset tests audit logs with offset pagination
func TestNewGetAuditLogsHandler_WithOffset(t *testing.T) {
	mockRepo := new(MockAuditLogRepository)
	auditLogs := []models.AuditLog{
		{
			ID:        21,
			UserID:    5,
			Action:    "rule.deleted",
			Status:    "failure",
			CreatedAt: time.Now(),
		},
	}

	mockRepo.On("FindPaginated", mock.Anything, 20, 20).Return(auditLogs, int64(100), nil)

	auditLogService := service.NewAuditLogService(mockRepo)
	handler := internalapi.NewGetAuditLogsHandler(auditLogService)

	router := gin.New()
	router.GET("/audit-logs", handler)

	req, _ := http.NewRequest("GET", "/audit-logs?limit=20&offset=20", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	mockRepo.AssertExpectations(t)
}

// TestNewGetAuditLogsHandler_InvalidLimit tests handling of invalid limit parameter
func TestNewGetAuditLogsHandler_InvalidLimit(t *testing.T) {
	mockRepo := new(MockAuditLogRepository)
	auditLogService := service.NewAuditLogService(mockRepo)
	handler := internalapi.NewGetAuditLogsHandler(auditLogService)

	router := gin.New()
	router.GET("/audit-logs", handler)

	req, _ := http.NewRequest("GET", "/audit-logs?limit=invalid", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestNewGetAuditLogsHandler_InvalidOffset tests handling of invalid offset parameter
func TestNewGetAuditLogsHandler_InvalidOffset(t *testing.T) {
	mockRepo := new(MockAuditLogRepository)
	auditLogService := service.NewAuditLogService(mockRepo)
	handler := internalapi.NewGetAuditLogsHandler(auditLogService)

	router := gin.New()
	router.GET("/audit-logs", handler)

	req, _ := http.NewRequest("GET", "/audit-logs?offset=invalid", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestNewGetAuditLogsHandler_ServiceError tests handling of service errors
func TestNewGetAuditLogsHandler_ServiceError(t *testing.T) {
	mockRepo := new(MockAuditLogRepository)
	mockRepo.On("FindPaginated", mock.Anything, 0, 20).Return(nil, int64(0), fmt.Errorf("database error"))

	auditLogService := service.NewAuditLogService(mockRepo)
	handler := internalapi.NewGetAuditLogsHandler(auditLogService)

	router := gin.New()
	router.GET("/audit-logs", handler)

	req, _ := http.NewRequest("GET", "/audit-logs", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	mockRepo.AssertExpectations(t)
}

// TestNewGetAuditLogsHandler_EmptyList tests handling of empty audit logs list
func TestNewGetAuditLogsHandler_EmptyList(t *testing.T) {
	mockRepo := new(MockAuditLogRepository)
	mockRepo.On("FindPaginated", mock.Anything, 0, 20).Return([]models.AuditLog{}, int64(0), nil)

	auditLogService := service.NewAuditLogService(mockRepo)
	handler := internalapi.NewGetAuditLogsHandler(auditLogService)

	router := gin.New()
	router.GET("/audit-logs", handler)

	req, _ := http.NewRequest("GET", "/audit-logs", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.NotNil(t, response["audit_logs"])
	assert.NotNil(t, response["pagination"])

	mockRepo.AssertExpectations(t)
}

// TestNewGetAuditLogStatsHandler_Success tests successful audit log statistics retrieval
func TestNewGetAuditLogStatsHandler_Success(t *testing.T) {
	mockRepo := new(MockAuditLogRepository)
	mockRepo.On("Count", mock.Anything).Return(int64(100), nil)
	mockRepo.On("CountByStatus", mock.Anything, "success").Return(int64(85), nil)
	mockRepo.On("CountByStatus", mock.Anything, "failure").Return(int64(15), nil)
	mockRepo.On("GetActionBreakdown", mock.Anything).Return(map[string]int64{
		"user.login":     50,
		"rule.created":   20,
		"rule.deleted":   15,
		"user.logout":    15,
	}, nil)

	auditLogService := service.NewAuditLogService(mockRepo)
	handler := internalapi.NewGetAuditLogStatsHandler(auditLogService)

	router := gin.New()
	router.GET("/audit-logs/stats", handler)

	req, _ := http.NewRequest("GET", "/audit-logs/stats", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)

	assert.Equal(t, float64(100), response["total_actions"])
	assert.Equal(t, float64(85), response["successful_actions"])
	assert.Equal(t, float64(15), response["failed_actions"])
	assert.NotNil(t, response["action_breakdown"])

	mockRepo.AssertExpectations(t)
}

// TestNewGetAuditLogStatsHandler_CountErrors tests handling when some counts fail
func TestNewGetAuditLogStatsHandler_CountErrors(t *testing.T) {
	mockRepo := new(MockAuditLogRepository)
	mockRepo.On("Count", mock.Anything).Return(int64(100), fmt.Errorf("count error"))
	mockRepo.On("CountByStatus", mock.Anything, "success").Return(int64(0), fmt.Errorf("count error"))
	mockRepo.On("CountByStatus", mock.Anything, "failure").Return(int64(0), fmt.Errorf("count error"))
	mockRepo.On("GetActionBreakdown", mock.Anything).Return(map[string]int64{}, fmt.Errorf("breakdown error"))

	auditLogService := service.NewAuditLogService(mockRepo)
	handler := internalapi.NewGetAuditLogStatsHandler(auditLogService)

	router := gin.New()
	router.GET("/audit-logs/stats", handler)

	req, _ := http.NewRequest("GET", "/audit-logs/stats", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)

	// Even with errors, should return response with default values
	assert.NotNil(t, response["total_actions"])
	assert.NotNil(t, response["successful_actions"])
	assert.NotNil(t, response["failed_actions"])
	assert.NotNil(t, response["action_breakdown"])

	mockRepo.AssertExpectations(t)
}

// TestNewGetAuditLogStatsHandler_EmptyStats tests audit log stats with empty data
func TestNewGetAuditLogStatsHandler_EmptyStats(t *testing.T) {
	mockRepo := new(MockAuditLogRepository)
	mockRepo.On("Count", mock.Anything).Return(int64(0), nil)
	mockRepo.On("CountByStatus", mock.Anything, "success").Return(int64(0), nil)
	mockRepo.On("CountByStatus", mock.Anything, "failure").Return(int64(0), nil)
	mockRepo.On("GetActionBreakdown", mock.Anything).Return(map[string]int64{}, nil)

	auditLogService := service.NewAuditLogService(mockRepo)
	handler := internalapi.NewGetAuditLogStatsHandler(auditLogService)

	router := gin.New()
	router.GET("/audit-logs/stats", handler)

	req, _ := http.NewRequest("GET", "/audit-logs/stats", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)

	assert.Equal(t, float64(0), response["total_actions"])
	assert.Equal(t, float64(0), response["successful_actions"])
	assert.Equal(t, float64(0), response["failed_actions"])

	mockRepo.AssertExpectations(t)
}

// TestNewGetAuditLogStatsHandler_LargeNumbers tests audit log stats with large numbers
func TestNewGetAuditLogStatsHandler_LargeNumbers(t *testing.T) {
	mockRepo := new(MockAuditLogRepository)
	mockRepo.On("Count", mock.Anything).Return(int64(1000000), nil)
	mockRepo.On("CountByStatus", mock.Anything, "success").Return(int64(999000), nil)
	mockRepo.On("CountByStatus", mock.Anything, "failure").Return(int64(1000), nil)
	mockRepo.On("GetActionBreakdown", mock.Anything).Return(map[string]int64{
		"user.login":        500000,
		"rule.created":      250000,
		"rule.updated":      150000,
		"rule.deleted":      100000,
	}, nil)

	auditLogService := service.NewAuditLogService(mockRepo)
	handler := internalapi.NewGetAuditLogStatsHandler(auditLogService)

	router := gin.New()
	router.GET("/audit-logs/stats", handler)

	req, _ := http.NewRequest("GET", "/audit-logs/stats", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)

	assert.Equal(t, float64(1000000), response["total_actions"])
	assert.Equal(t, float64(999000), response["successful_actions"])
	assert.Equal(t, float64(1000), response["failed_actions"])

	mockRepo.AssertExpectations(t)
}

// TestNewGetAuditLogStatsHandler_ActionBreakdownError tests handling when action breakdown fails
func TestNewGetAuditLogStatsHandler_ActionBreakdownError(t *testing.T) {
	mockRepo := new(MockAuditLogRepository)
	mockRepo.On("Count", mock.Anything).Return(int64(100), nil)
	mockRepo.On("CountByStatus", mock.Anything, "success").Return(int64(85), nil)
	mockRepo.On("CountByStatus", mock.Anything, "failure").Return(int64(15), nil)
	mockRepo.On("GetActionBreakdown", mock.Anything).Return(nil, fmt.Errorf("breakdown error"))

	auditLogService := service.NewAuditLogService(mockRepo)
	handler := internalapi.NewGetAuditLogStatsHandler(auditLogService)

	router := gin.New()
	router.GET("/audit-logs/stats", handler)

	req, _ := http.NewRequest("GET", "/audit-logs/stats", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)

	// Should still return other counts, with empty breakdown
	assert.Equal(t, float64(100), response["total_actions"])
	assert.Equal(t, float64(85), response["successful_actions"])
	assert.Equal(t, float64(15), response["failed_actions"])
	assert.NotNil(t, response["action_breakdown"])

	mockRepo.AssertExpectations(t)
}

// TestNewGetAuditLogsHandler_MaxLimit tests audit logs with max limit
func TestNewGetAuditLogsHandler_MaxLimit(t *testing.T) {
	mockRepo := new(MockAuditLogRepository)
	auditLogs := make([]models.AuditLog, 100)
	for i := 0; i < 100; i++ {
		auditLogs[i] = models.AuditLog{
			ID:        uint(i + 1),
			UserID:    1,
			Action:    "user.action",
			Status:    "success",
			CreatedAt: time.Now(),
		}
	}

	mockRepo.On("FindPaginated", mock.Anything, 0, 100).Return(auditLogs, int64(500), nil)

	auditLogService := service.NewAuditLogService(mockRepo)
	handler := internalapi.NewGetAuditLogsHandler(auditLogService)

	router := gin.New()
	router.GET("/audit-logs", handler)

	req, _ := http.NewRequest("GET", "/audit-logs?limit=100", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	mockRepo.AssertExpectations(t)
}

// TestNewGetAuditLogsHandler_LargeOffset tests audit logs with large offset
func TestNewGetAuditLogsHandler_LargeOffset(t *testing.T) {
	mockRepo := new(MockAuditLogRepository)
	auditLogs := []models.AuditLog{
		{
			ID:        401,
			UserID:    100,
			Action:    "user.login",
			Status:    "success",
			CreatedAt: time.Now(),
		},
	}

	mockRepo.On("FindPaginated", mock.Anything, 400, 20).Return(auditLogs, int64(1000), nil)

	auditLogService := service.NewAuditLogService(mockRepo)
	handler := internalapi.NewGetAuditLogsHandler(auditLogService)

	router := gin.New()
	router.GET("/audit-logs", handler)

	req, _ := http.NewRequest("GET", "/audit-logs?limit=20&offset=400", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	mockRepo.AssertExpectations(t)
}
