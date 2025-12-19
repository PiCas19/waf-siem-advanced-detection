// tests/service/log_service_test.go
package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/service"
	"github.com/stretchr/testify/assert"
)

func TestNewLogService(t *testing.T) {
	mockRepo := &MockLogRepository{}
	svc := service.NewLogService(mockRepo)
	
	assert.NotNil(t, svc)
}

func TestLogService_GetAllLogs(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		expected := []models.Log{
			{ID: 1, ClientIP: "192.168.1.1", ThreatType: "xss"},
			{ID: 2, ClientIP: "192.168.1.2", ThreatType: "sql_injection"},
		}
		
		mockRepo.On("FindAll", ctx).Return(expected, nil)
		
		result, err := svc.GetAllLogs(ctx)
		
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("FindAll", ctx).Return([]models.Log{}, expectedErr)
		
		result, err := svc.GetAllLogs(ctx)
		
		assert.Error(t, err)
		assert.Empty(t, result)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
}

func TestLogService_GetLogsPaginated(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		expected := []models.Log{
			{ID: 1, ClientIP: "192.168.1.1", ThreatType: "xss"},
		}
		var expectedTotal int64 = 100
		
		mockRepo.On("FindPaginated", ctx, 0, 10).Return(expected, expectedTotal, nil)
		
		result, total, err := svc.GetLogsPaginated(ctx, 0, 10)
		
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
		assert.Equal(t, expectedTotal, total)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("FindPaginated", ctx, 0, 10).Return([]models.Log{}, int64(0), expectedErr)
		
		result, total, err := svc.GetLogsPaginated(ctx, 0, 10)
		
		assert.Error(t, err)
		assert.Empty(t, result)
		assert.Zero(t, total)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
}

// ... (tutti gli altri test per LogService) ...

func TestLogService_DeleteManualBlockLog(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		mockRepo.On("DeleteManualBlockLog", ctx, "192.168.1.1", "SQL injection").Return(nil)
		
		err := svc.DeleteManualBlockLog(ctx, "192.168.1.1", "SQL injection")
		
		assert.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("EmptyIP", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		err := svc.DeleteManualBlockLog(ctx, "", "SQL injection")
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "IP and description cannot be empty")
		mockRepo.AssertNotCalled(t, "DeleteManualBlockLog")
	})
	
	t.Run("EmptyDescription", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		err := svc.DeleteManualBlockLog(ctx, "192.168.1.1", "")
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "IP and description cannot be empty")
		mockRepo.AssertNotCalled(t, "DeleteManualBlockLog")
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("DeleteManualBlockLog", ctx, "192.168.1.1", "SQL injection").Return(expectedErr)
		
		err := svc.DeleteManualBlockLog(ctx, "192.168.1.1", "SQL injection")
		
		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
}

// tests/service/log_service_test.go (aggiungi questi test)
func TestLogService_GetLogByID(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		expected := &models.Log{
			ID:         1,
			ClientIP:   "192.168.1.1",
			ThreatType: "xss",
			Blocked:    true,
		}
		
		mockRepo.On("FindByID", ctx, uint(1)).Return(expected, nil)
		
		result, err := svc.GetLogByID(ctx, 1)
		
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("NotFound", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		mockRepo.On("FindByID", ctx, uint(1)).Return((*models.Log)(nil), nil)
		
		result, err := svc.GetLogByID(ctx, 1)
		
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "log not found")
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("FindByID", ctx, uint(1)).Return((*models.Log)(nil), expectedErr)
		
		result, err := svc.GetLogByID(ctx, 1)
		
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "failed to get log")
		assert.Contains(t, err.Error(), "database error")
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("ValidIDZero", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		// NOTA: ID 0 è valido per GetLogByID (non c'è validazione su ID=0)
		// Solo DeleteLog e UpdateLog validano ID != 0
		expected := &models.Log{
			ID:         0,
			ClientIP:   "192.168.1.1",
			ThreatType: "test",
		}
		
		mockRepo.On("FindByID", ctx, uint(0)).Return(expected, nil)
		
		result, err := svc.GetLogByID(ctx, 0)
		
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
		mockRepo.AssertExpectations(t)
	})
}

func TestLogService_GetLogsByIP(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		expected := []models.Log{
			{ID: 1, ClientIP: "192.168.1.1", ThreatType: "xss"},
			{ID: 2, ClientIP: "192.168.1.1", ThreatType: "sql_injection"},
		}
		
		mockRepo.On("FindByIP", ctx, "192.168.1.1").Return(expected, nil)
		
		result, err := svc.GetLogsByIP(ctx, "192.168.1.1")
		
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("EmptyIP", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		result, err := svc.GetLogsByIP(ctx, "")
		
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "IP address cannot be empty")
		mockRepo.AssertNotCalled(t, "FindByIP")
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("FindByIP", ctx, "192.168.1.1").Return([]models.Log{}, expectedErr)
		
		result, err := svc.GetLogsByIP(ctx, "192.168.1.1")
		
		assert.Error(t, err)
		assert.Empty(t, result)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("NoLogsFound", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		mockRepo.On("FindByIP", ctx, "192.168.1.99").Return([]models.Log{}, nil)
		
		result, err := svc.GetLogsByIP(ctx, "192.168.1.99")
		
		assert.NoError(t, err)
		assert.Empty(t, result)
		mockRepo.AssertExpectations(t)
	})
}

func TestLogService_GetBlockedLogs(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		expected := []models.Log{
			{ID: 1, ClientIP: "192.168.1.1", ThreatType: "xss", Blocked: true},
			{ID: 2, ClientIP: "192.168.1.2", ThreatType: "sql_injection", Blocked: true},
		}
		
		mockRepo.On("FindBlocked", ctx).Return(expected, nil)
		
		result, err := svc.GetBlockedLogs(ctx)
		
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("FindBlocked", ctx).Return([]models.Log{}, expectedErr)
		
		result, err := svc.GetBlockedLogs(ctx)
		
		assert.Error(t, err)
		assert.Empty(t, result)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("NoBlockedLogs", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		mockRepo.On("FindBlocked", ctx).Return([]models.Log{}, nil)
		
		result, err := svc.GetBlockedLogs(ctx)
		
		assert.NoError(t, err)
		assert.Empty(t, result)
		mockRepo.AssertExpectations(t)
	})
}

func TestLogService_GetLogsByThreatType(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		expected := []models.Log{
			{ID: 1, ClientIP: "192.168.1.1", ThreatType: "xss"},
			{ID: 2, ClientIP: "192.168.1.2", ThreatType: "xss"},
		}
		
		mockRepo.On("FindByThreatType", ctx, "xss").Return(expected, nil)
		
		result, err := svc.GetLogsByThreatType(ctx, "xss")
		
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("EmptyThreatType", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		result, err := svc.GetLogsByThreatType(ctx, "")
		
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "threat type cannot be empty")
		mockRepo.AssertNotCalled(t, "FindByThreatType")
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("FindByThreatType", ctx, "xss").Return([]models.Log{}, expectedErr)
		
		result, err := svc.GetLogsByThreatType(ctx, "xss")
		
		assert.Error(t, err)
		assert.Empty(t, result)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("ThreatTypeNotFound", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		mockRepo.On("FindByThreatType", ctx, "unknown").Return([]models.Log{}, nil)
		
		result, err := svc.GetLogsByThreatType(ctx, "unknown")
		
		assert.NoError(t, err)
		assert.Empty(t, result)
		mockRepo.AssertExpectations(t)
	})
}

func TestLogService_GetRecentLogs(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		expected := []models.Log{
			{ID: 1, ClientIP: "192.168.1.1", ThreatType: "xss"},
			{ID: 2, ClientIP: "192.168.1.2", ThreatType: "sql_injection"},
		}
		
		mockRepo.On("FindRecent", ctx, 10).Return(expected, nil)
		
		result, err := svc.GetRecentLogs(ctx, 10)
		
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("InvalidLimitZero", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		result, err := svc.GetRecentLogs(ctx, 0)
		
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "limit must be positive")
		mockRepo.AssertNotCalled(t, "FindRecent")
	})
	
	t.Run("InvalidLimitNegative", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		result, err := svc.GetRecentLogs(ctx, -5)
		
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "limit must be positive")
		mockRepo.AssertNotCalled(t, "FindRecent")
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("FindRecent", ctx, 5).Return([]models.Log{}, expectedErr)
		
		result, err := svc.GetRecentLogs(ctx, 5)
		
		assert.Error(t, err)
		assert.Empty(t, result)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("LimitOne", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		expected := []models.Log{
			{ID: 1, ClientIP: "192.168.1.1", ThreatType: "xss"},
		}
		
		mockRepo.On("FindRecent", ctx, 1).Return(expected, nil)
		
		result, err := svc.GetRecentLogs(ctx, 1)
		
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
		mockRepo.AssertExpectations(t)
	})
}

func TestLogService_GetLogsCount(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		var expectedCount int64 = 150
		mockRepo.On("Count", ctx).Return(expectedCount, nil)
		
		count, err := svc.GetLogsCount(ctx)
		
		assert.NoError(t, err)
		assert.Equal(t, expectedCount, count)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("Count", ctx).Return(int64(0), expectedErr)
		
		count, err := svc.GetLogsCount(ctx)
		
		assert.Error(t, err)
		assert.Zero(t, count)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("ZeroLogs", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		mockRepo.On("Count", ctx).Return(int64(0), nil)
		
		count, err := svc.GetLogsCount(ctx)
		
		assert.NoError(t, err)
		assert.Zero(t, count)
		mockRepo.AssertExpectations(t)
	})
}

func TestLogService_GetBlockedLogsCount(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		var expectedCount int64 = 25
		mockRepo.On("CountBlocked", ctx).Return(expectedCount, nil)
		
		count, err := svc.GetBlockedLogsCount(ctx)
		
		assert.NoError(t, err)
		assert.Equal(t, expectedCount, count)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("CountBlocked", ctx).Return(int64(0), expectedErr)
		
		count, err := svc.GetBlockedLogsCount(ctx)
		
		assert.Error(t, err)
		assert.Zero(t, count)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("ZeroBlockedLogs", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		mockRepo.On("CountBlocked", ctx).Return(int64(0), nil)
		
		count, err := svc.GetBlockedLogsCount(ctx)
		
		assert.NoError(t, err)
		assert.Zero(t, count)
		mockRepo.AssertExpectations(t)
	})
}

func TestLogService_CreateLog(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		log := &models.Log{
			ClientIP:   "192.168.1.1",
			ThreatType: "xss",
			URL:        "/api/test",
			Blocked:    true,
			BlockedBy:  "auto",
		}
		
		mockRepo.On("Create", ctx, log).Return(nil)
		
		err := svc.CreateLog(ctx, log)
		
		assert.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("NilLog", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		err := svc.CreateLog(ctx, nil)
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "log cannot be nil")
		mockRepo.AssertNotCalled(t, "Create")
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		log := &models.Log{
			ClientIP:   "192.168.1.1",
			ThreatType: "xss",
		}
		
		expectedErr := errors.New("database error")
		mockRepo.On("Create", ctx, log).Return(expectedErr)
		
		err := svc.CreateLog(ctx, log)
		
		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("LogWithAllFields", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		now := time.Now()
		log := &models.Log{
			ID:          1,
			CreatedAt:   now,
			ThreatType:  "sql_injection",
			Severity:    "high",
			Description: "SQL injection attempt detected",
			ClientIP:    "203.0.113.42",
			Method:      "POST",
			URL:         "/api/login",
			UserAgent:   "Mozilla/5.0",
			Payload:     "' OR '1'='1",
			Blocked:     true,
			BlockedBy:   "manual",
			IPReputation: intPtr(85),
			IsMalicious:  true,
			Country:      "US",
		}
		
		mockRepo.On("Create", ctx, log).Return(nil)
		
		err := svc.CreateLog(ctx, log)
		
		assert.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})
}

// Helper per creare puntatori a int
func intPtr(i int) *int {
	return &i
}

func TestLogService_UpdateLog(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		log := &models.Log{
			ID:         1,
			ClientIP:   "192.168.1.1",
			ThreatType: "xss",
			Blocked:    true,
			BlockedBy:  "manual",
		}
		
		mockRepo.On("Update", ctx, log).Return(nil)
		
		err := svc.UpdateLog(ctx, log)
		
		assert.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("NilLog", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		err := svc.UpdateLog(ctx, nil)
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "log cannot be nil")
		mockRepo.AssertNotCalled(t, "Update")
	})
	
	t.Run("ZeroID", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		log := &models.Log{
			ClientIP:   "192.168.1.1",
			ThreatType: "xss",
		}
		
		err := svc.UpdateLog(ctx, log)
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "log ID must be set")
		mockRepo.AssertNotCalled(t, "Update")
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		log := &models.Log{
			ID:         1,
			ClientIP:   "192.168.1.1",
			ThreatType: "xss",
		}
		
		expectedErr := errors.New("database error")
		mockRepo.On("Update", ctx, log).Return(expectedErr)
		
		err := svc.UpdateLog(ctx, log)
		
		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("PartialUpdate", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		log := &models.Log{
			ID:         1,
			ClientIP:   "192.168.1.1",
			// Solo alcuni campi aggiornati
			Blocked:   true,
			BlockedBy: "manual",
		}
		
		mockRepo.On("Update", ctx, log).Return(nil)
		
		err := svc.UpdateLog(ctx, log)
		
		assert.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})
}

func TestLogService_DeleteLog(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		mockRepo.On("Delete", ctx, uint(1)).Return(nil)
		
		err := svc.DeleteLog(ctx, 1)
		
		assert.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("ZeroID", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		err := svc.DeleteLog(ctx, 0)
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "log ID must be set")
		mockRepo.AssertNotCalled(t, "Delete")
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("Delete", ctx, uint(1)).Return(expectedErr)
		
		err := svc.DeleteLog(ctx, 1)
		
		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
}

func TestLogService_GetPaginatedLogs(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		expected := []models.Log{
			{ID: 1, ClientIP: "192.168.1.1", ThreatType: "xss"},
			{ID: 2, ClientIP: "192.168.1.2", ThreatType: "sql_injection"},
		}
		var expectedTotal int64 = 100
		
		mockRepo.On("FindPaginated", ctx, 0, 10).Return(expected, expectedTotal, nil)
		
		result, total, err := svc.GetPaginatedLogs(ctx, 1, 10)
		
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
		assert.Equal(t, expectedTotal, total)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("Page2", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		expected := []models.Log{
			{ID: 11, ClientIP: "192.168.1.11", ThreatType: "xss"},
			{ID: 12, ClientIP: "192.168.1.12", ThreatType: "lfi"},
		}
		var expectedTotal int64 = 100
		
		mockRepo.On("FindPaginated", ctx, 10, 10).Return(expected, expectedTotal, nil)
		
		result, total, err := svc.GetPaginatedLogs(ctx, 2, 10)
		
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
		assert.Equal(t, expectedTotal, total)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("InvalidPageZero", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		result, total, err := svc.GetPaginatedLogs(ctx, 0, 10)
		
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Zero(t, total)
		assert.Contains(t, err.Error(), "page and pageSize must be positive")
		mockRepo.AssertNotCalled(t, "FindPaginated")
	})
	
	t.Run("InvalidPageNegative", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		result, total, err := svc.GetPaginatedLogs(ctx, -1, 10)
		
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Zero(t, total)
		assert.Contains(t, err.Error(), "page and pageSize must be positive")
		mockRepo.AssertNotCalled(t, "FindPaginated")
	})
	
	t.Run("InvalidPageSizeZero", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		result, total, err := svc.GetPaginatedLogs(ctx, 1, 0)
		
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Zero(t, total)
		assert.Contains(t, err.Error(), "page and pageSize must be positive")
		mockRepo.AssertNotCalled(t, "FindPaginated")
	})
	
	t.Run("InvalidPageSizeNegative", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		result, total, err := svc.GetPaginatedLogs(ctx, 1, -5)
		
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Zero(t, total)
		assert.Contains(t, err.Error(), "page and pageSize must be positive")
		mockRepo.AssertNotCalled(t, "FindPaginated")
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("FindPaginated", ctx, 0, 10).Return([]models.Log{}, int64(0), expectedErr)
		
		result, total, err := svc.GetPaginatedLogs(ctx, 1, 10)
		
		assert.Error(t, err)
		assert.Empty(t, result)
		assert.Zero(t, total)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("EmptyResults", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		mockRepo.On("FindPaginated", ctx, 0, 10).Return([]models.Log{}, int64(0), nil)
		
		result, total, err := svc.GetPaginatedLogs(ctx, 1, 10)
		
		assert.NoError(t, err)
		assert.Empty(t, result)
		assert.Zero(t, total)
		mockRepo.AssertExpectations(t)
	})
}

func TestLogService_UpdateLogsByIPAndDescription(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		updates := map[string]interface{}{
			"blocked":    true,
			"blocked_by": "manual",
			"is_malicious": true,
		}
		
		mockRepo.On("UpdateByIPAndDescription", ctx, "192.168.1.1", "SQL injection", updates).Return(nil)
		
		err := svc.UpdateLogsByIPAndDescription(ctx, "192.168.1.1", "SQL injection", updates)
		
		assert.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("EmptyIP", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		updates := map[string]interface{}{
			"blocked": true,
		}
		
		err := svc.UpdateLogsByIPAndDescription(ctx, "", "SQL injection", updates)
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "IP and description cannot be empty")
		mockRepo.AssertNotCalled(t, "UpdateByIPAndDescription")
	})
	
	t.Run("EmptyDescription", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		updates := map[string]interface{}{
			"blocked": true,
		}
		
		err := svc.UpdateLogsByIPAndDescription(ctx, "192.168.1.1", "", updates)
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "IP and description cannot be empty")
		mockRepo.AssertNotCalled(t, "UpdateByIPAndDescription")
	})
	
	t.Run("EmptyUpdates", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		err := svc.UpdateLogsByIPAndDescription(ctx, "192.168.1.1", "SQL injection", map[string]interface{}{})
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "updates cannot be empty")
		mockRepo.AssertNotCalled(t, "UpdateByIPAndDescription")
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		updates := map[string]interface{}{
			"blocked": true,
		}
		expectedErr := errors.New("database error")
		
		mockRepo.On("UpdateByIPAndDescription", ctx, "192.168.1.1", "SQL injection", updates).Return(expectedErr)
		
		err := svc.UpdateLogsByIPAndDescription(ctx, "192.168.1.1", "SQL injection", updates)
		
		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
}

func TestLogService_UpdateDetectedLogsByIPAndDescription(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		updates := map[string]interface{}{
			"blocked":    true,
			"blocked_by": "manual",
			"is_malicious": true,
		}
		
		mockRepo.On("UpdateDetectedByIPAndDescription", ctx, "192.168.1.1", "SQL injection", updates).Return(nil)
		
		err := svc.UpdateDetectedLogsByIPAndDescription(ctx, "192.168.1.1", "SQL injection", updates)
		
		assert.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("EmptyIP", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		updates := map[string]interface{}{
			"blocked": true,
		}
		
		err := svc.UpdateDetectedLogsByIPAndDescription(ctx, "", "SQL injection", updates)
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "IP and description cannot be empty")
		mockRepo.AssertNotCalled(t, "UpdateDetectedByIPAndDescription")
	})
	
	t.Run("EmptyDescription", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		updates := map[string]interface{}{
			"blocked": true,
		}
		
		err := svc.UpdateDetectedLogsByIPAndDescription(ctx, "192.168.1.1", "", updates)
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "IP and description cannot be empty")
		mockRepo.AssertNotCalled(t, "UpdateDetectedByIPAndDescription")
	})
	
	t.Run("EmptyUpdates", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		err := svc.UpdateDetectedLogsByIPAndDescription(ctx, "192.168.1.1", "SQL injection", map[string]interface{}{})
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "updates cannot be empty")
		mockRepo.AssertNotCalled(t, "UpdateDetectedByIPAndDescription")
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		updates := map[string]interface{}{
			"blocked": true,
		}
		expectedErr := errors.New("database error")
		
		mockRepo.On("UpdateDetectedByIPAndDescription", ctx, "192.168.1.1", "SQL injection", updates).Return(expectedErr)
		
		err := svc.UpdateDetectedLogsByIPAndDescription(ctx, "192.168.1.1", "SQL injection", updates)
		
		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("SingleUpdateField", func(t *testing.T) {
		mockRepo := &MockLogRepository{}
		svc := service.NewLogService(mockRepo)
		ctx := context.Background()
		
		updates := map[string]interface{}{
			"blocked": true,
		}
		
		mockRepo.On("UpdateDetectedByIPAndDescription", ctx, "192.168.1.1", "XSS attempt", updates).Return(nil)
		
		err := svc.UpdateDetectedLogsByIPAndDescription(ctx, "192.168.1.1", "XSS attempt", updates)
		
		assert.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})
}