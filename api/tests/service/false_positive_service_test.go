// tests/service/false_positive_service_test.go
package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestNewFalsePositiveService(t *testing.T) {
	mockRepo := &MockFalsePositiveRepository{}
	svc := service.NewFalsePositiveService(mockRepo)
	
	assert.NotNil(t, svc)
}

func TestFalsePositiveService_GetAllFalsePositives(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		expected := []models.FalsePositive{
			{ID: 1, ClientIP: "192.168.1.1", ThreatType: "xss"},
			{ID: 2, ClientIP: "192.168.1.2", ThreatType: "sql_injection"},
		}
		
		mockRepo.On("FindAll", ctx).Return(expected, nil)
		
		result, err := svc.GetAllFalsePositives(ctx)
		
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("FindAll", ctx).Return([]models.FalsePositive{}, expectedErr)
		
		result, err := svc.GetAllFalsePositives(ctx)
		
		assert.Error(t, err)
		assert.Empty(t, result)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
}

func TestFalsePositiveService_GetFalsePositivesPaginated(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		expected := []models.FalsePositive{
			{ID: 1, ClientIP: "192.168.1.1", ThreatType: "xss"},
		}
		var expectedTotal int64 = 100
		
		mockRepo.On("FindPaginated", ctx, 0, 10).Return(expected, expectedTotal, nil)
		
		result, total, err := svc.GetFalsePositivesPaginated(ctx, 0, 10)
		
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
		assert.Equal(t, expectedTotal, total)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("FindPaginated", ctx, 0, 10).Return([]models.FalsePositive{}, int64(0), expectedErr)
		
		result, total, err := svc.GetFalsePositivesPaginated(ctx, 0, 10)
		
		assert.Error(t, err)
		assert.Empty(t, result)
		assert.Zero(t, total)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
}

func TestFalsePositiveService_GetFalsePositiveByID(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		expected := &models.FalsePositive{
			ID:         1,
			ClientIP:   "192.168.1.1",
			ThreatType: "xss",
		}
		
		mockRepo.On("FindByID", ctx, uint(1)).Return(expected, nil)
		
		result, err := svc.GetFalsePositiveByID(ctx, 1)
		
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("NotFound", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		mockRepo.On("FindByID", ctx, uint(1)).Return((*models.FalsePositive)(nil), nil)
		
		result, err := svc.GetFalsePositiveByID(ctx, 1)
		
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "false positive not found")
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("FindByID", ctx, uint(1)).Return((*models.FalsePositive)(nil), expectedErr)
		
		result, err := svc.GetFalsePositiveByID(ctx, 1)
		
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "failed to get false positive")
		assert.Contains(t, err.Error(), "database error")
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("InvalidID", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		result, err := svc.GetFalsePositiveByID(ctx, 0)
		
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "false positive ID must be set")
		mockRepo.AssertNotCalled(t, "FindByID")
	})
}

func TestFalsePositiveService_GetFalsePositivesByIP(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		expected := []models.FalsePositive{
			{ID: 1, ClientIP: "192.168.1.1", ThreatType: "xss"},
			{ID: 2, ClientIP: "192.168.1.1", ThreatType: "sql_injection"},
		}
		
		mockRepo.On("FindByIP", ctx, "192.168.1.1").Return(expected, nil)
		
		result, err := svc.GetFalsePositivesByIP(ctx, "192.168.1.1")
		
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("EmptyIP", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		result, err := svc.GetFalsePositivesByIP(ctx, "")
		
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "client IP cannot be empty")
		mockRepo.AssertNotCalled(t, "FindByIP")
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("FindByIP", ctx, "192.168.1.1").Return([]models.FalsePositive{}, expectedErr)
		
		result, err := svc.GetFalsePositivesByIP(ctx, "192.168.1.1")
		
		assert.Error(t, err)
		assert.Empty(t, result)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
}

func TestFalsePositiveService_GetUnresolvedFalsePositives(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		expected := []models.FalsePositive{
			{ID: 1, ClientIP: "192.168.1.1", ThreatType: "xss", Status: "pending"},
			{ID: 2, ClientIP: "192.168.1.2", ThreatType: "sql_injection", Status: "pending"},
		}
		
		mockRepo.On("FindUnresolved", ctx).Return(expected, nil)
		
		result, err := svc.GetUnresolvedFalsePositives(ctx)
		
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("FindUnresolved", ctx).Return([]models.FalsePositive{}, expectedErr)
		
		result, err := svc.GetUnresolvedFalsePositives(ctx)
		
		assert.Error(t, err)
		assert.Empty(t, result)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
}

func TestFalsePositiveService_GetFalsePositivesCount(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		var expectedCount int64 = 150
		mockRepo.On("Count", ctx).Return(expectedCount, nil)
		
		count, err := svc.GetFalsePositivesCount(ctx)
		
		assert.NoError(t, err)
		assert.Equal(t, expectedCount, count)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("Count", ctx).Return(int64(0), expectedErr)
		
		count, err := svc.GetFalsePositivesCount(ctx)
		
		assert.Error(t, err)
		assert.Zero(t, count)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
}

func TestFalsePositiveService_GetUnresolvedCount(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		var expectedCount int64 = 25
		mockRepo.On("CountUnresolved", ctx).Return(expectedCount, nil)
		
		count, err := svc.GetUnresolvedCount(ctx)
		
		assert.NoError(t, err)
		assert.Equal(t, expectedCount, count)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("CountUnresolved", ctx).Return(int64(0), expectedErr)
		
		count, err := svc.GetUnresolvedCount(ctx)
		
		assert.Error(t, err)
		assert.Zero(t, count)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
}

func TestFalsePositiveService_ReportFalsePositive(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		fp := &models.FalsePositive{
			ClientIP:   "192.168.1.1",
			ThreatType: "xss",
			URL:        "/api/test",
		}
		
		mockRepo.On("Create", ctx, fp).Return(nil)
		
		err := svc.ReportFalsePositive(ctx, fp)
		
		assert.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("NilFalsePositive", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		err := svc.ReportFalsePositive(ctx, nil)
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "false positive cannot be nil")
		mockRepo.AssertNotCalled(t, "Create")
	})
	
	t.Run("EmptyClientIP", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		fp := &models.FalsePositive{
			ThreatType: "xss",
		}
		
		err := svc.ReportFalsePositive(ctx, fp)
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "client IP cannot be empty")
		mockRepo.AssertNotCalled(t, "Create")
	})
	
	t.Run("EmptyThreatType", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		fp := &models.FalsePositive{
			ClientIP: "192.168.1.1",
		}
		
		err := svc.ReportFalsePositive(ctx, fp)
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "threat type cannot be empty")
		mockRepo.AssertNotCalled(t, "Create")
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		fp := &models.FalsePositive{
			ClientIP:   "192.168.1.1",
			ThreatType: "xss",
		}
		
		expectedErr := errors.New("database error")
		mockRepo.On("Create", ctx, fp).Return(expectedErr)
		
		err := svc.ReportFalsePositive(ctx, fp)
		
		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
}

func TestFalsePositiveService_UpdateFalsePositive(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		fp := &models.FalsePositive{
			ID:         1,
			ClientIP:   "192.168.1.1",
			ThreatType: "xss",
			Status:     "reviewed",
		}
		
		mockRepo.On("Update", ctx, fp).Return(nil)
		
		err := svc.UpdateFalsePositive(ctx, fp)
		
		assert.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("NilFalsePositive", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		err := svc.UpdateFalsePositive(ctx, nil)
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "false positive cannot be nil")
		mockRepo.AssertNotCalled(t, "Update")
	})
	
	t.Run("ZeroID", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		fp := &models.FalsePositive{
			ClientIP:   "192.168.1.1",
			ThreatType: "xss",
		}
		
		err := svc.UpdateFalsePositive(ctx, fp)
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "false positive ID must be set")
		mockRepo.AssertNotCalled(t, "Update")
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		fp := &models.FalsePositive{
			ID:         1,
			ClientIP:   "192.168.1.1",
			ThreatType: "xss",
		}
		
		expectedErr := errors.New("database error")
		mockRepo.On("Update", ctx, fp).Return(expectedErr)
		
		err := svc.UpdateFalsePositive(ctx, fp)
		
		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
}

func TestFalsePositiveService_ReviewFalsePositive(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		now := time.Now()
		fp := &models.FalsePositive{
			ID:        1,
			ClientIP:  "192.168.1.1",
			CreatedAt: now,
		}
		
		mockRepo.On("FindByID", ctx, uint(1)).Return(fp, nil)
		mockRepo.On("Update", ctx, mock.MatchedBy(func(f *models.FalsePositive) bool {
			return f.ID == 1 &&
				f.Status == "approved" &&
				f.ReviewNotes == "Looks good" &&
				f.ReviewedBy == uint(100) &&
				f.ReviewedAt != nil
		})).Return(nil)
		
		err := svc.ReviewFalsePositive(ctx, 1, "approved", "Looks good", 100)
		
		assert.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("ZeroID", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		err := svc.ReviewFalsePositive(ctx, 0, "approved", "test", 1)
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "false positive ID must be set")
		mockRepo.AssertNotCalled(t, "FindByID")
	})
	
	t.Run("EmptyStatus", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		err := svc.ReviewFalsePositive(ctx, 1, "", "test", 1)
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "status cannot be empty")
		mockRepo.AssertNotCalled(t, "FindByID")
	})
	
	t.Run("NotFound", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		mockRepo.On("FindByID", ctx, uint(1)).Return((*models.FalsePositive)(nil), nil)
		
		err := svc.ReviewFalsePositive(ctx, 1, "approved", "test", 1)
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "false positive not found")
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("GetFalsePositiveByIDError", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("FindByID", ctx, uint(1)).Return((*models.FalsePositive)(nil), expectedErr)
		
		err := svc.ReviewFalsePositive(ctx, 1, "approved", "test", 1)
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get false positive")
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("UpdateError", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		now := time.Now()
		fp := &models.FalsePositive{
			ID:        1,
			ClientIP:  "192.168.1.1",
			CreatedAt: now,
		}
		
		expectedErr := errors.New("update error")
		mockRepo.On("FindByID", ctx, uint(1)).Return(fp, nil)
		mockRepo.On("Update", ctx, mock.AnythingOfType("*models.FalsePositive")).Return(expectedErr)
		
		err := svc.ReviewFalsePositive(ctx, 1, "approved", "test", 1)
		
		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
}

func TestFalsePositiveService_DeleteFalsePositive(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		mockRepo.On("Delete", ctx, uint(1)).Return(nil)
		
		err := svc.DeleteFalsePositive(ctx, 1)
		
		assert.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("ZeroID", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		err := svc.DeleteFalsePositive(ctx, 0)
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "false positive ID must be set")
		mockRepo.AssertNotCalled(t, "Delete")
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("Delete", ctx, uint(1)).Return(expectedErr)
		
		err := svc.DeleteFalsePositive(ctx, 1)
		
		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
}

func TestFalsePositiveService_GetPaginatedFalsePositives(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		expected := []models.FalsePositive{
			{ID: 1, ClientIP: "192.168.1.1", ThreatType: "xss"},
		}
		var expectedTotal int64 = 100
		
		mockRepo.On("FindPaginated", ctx, 0, 10).Return(expected, expectedTotal, nil)
		
		result, total, err := svc.GetPaginatedFalsePositives(ctx, 1, 10)
		
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
		assert.Equal(t, expectedTotal, total)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("Page2", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		expected := []models.FalsePositive{
			{ID: 11, ClientIP: "192.168.1.11", ThreatType: "xss"},
		}
		var expectedTotal int64 = 100
		
		mockRepo.On("FindPaginated", ctx, 10, 10).Return(expected, expectedTotal, nil)
		
		result, total, err := svc.GetPaginatedFalsePositives(ctx, 2, 10)
		
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
		assert.Equal(t, expectedTotal, total)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("InvalidPage", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		result, total, err := svc.GetPaginatedFalsePositives(ctx, 0, 10)
		
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Zero(t, total)
		assert.Contains(t, err.Error(), "page and pageSize must be positive")
		mockRepo.AssertNotCalled(t, "FindPaginated")
	})
	
	t.Run("InvalidPageSize", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		result, total, err := svc.GetPaginatedFalsePositives(ctx, 1, 0)
		
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Zero(t, total)
		assert.Contains(t, err.Error(), "page and pageSize must be positive")
		mockRepo.AssertNotCalled(t, "FindPaginated")
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockFalsePositiveRepository{}
		svc := service.NewFalsePositiveService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("FindPaginated", ctx, 0, 10).Return([]models.FalsePositive{}, int64(0), expectedErr)
		
		result, total, err := svc.GetPaginatedFalsePositives(ctx, 1, 10)
		
		assert.Error(t, err)
		assert.Empty(t, result)
		assert.Zero(t, total)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
}