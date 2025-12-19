// tests/service/whitelist_service_test.go
package service

import (
	"context"
	"errors"
	"testing"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/service"
	"github.com/stretchr/testify/assert"
)


func TestNewWhitelistService(t *testing.T) {
	mockRepo := &MockWhitelistedIPRepository{}
	svc := service.NewWhitelistService(mockRepo)
	
	assert.NotNil(t, svc)
}

func TestWhitelistService_GetAllWhitelistedIPs(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockWhitelistedIPRepository{}
		svc := service.NewWhitelistService(mockRepo)
		ctx := context.Background()
		
		expected := []models.WhitelistedIP{
			{ID: 1, IPAddress: "192.168.1.1", Reason: "Internal network", AddedBy: 1},
			{ID: 2, IPAddress: "10.0.0.1", Reason: "VPN gateway", AddedBy: 1},
		}
		
		mockRepo.On("FindAll", ctx).Return(expected, nil)
		
		result, err := svc.GetAllWhitelistedIPs(ctx)
		
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockWhitelistedIPRepository{}
		svc := service.NewWhitelistService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("FindAll", ctx).Return([]models.WhitelistedIP{}, expectedErr)
		
		result, err := svc.GetAllWhitelistedIPs(ctx)
		
		assert.Error(t, err)
		assert.Empty(t, result)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("NoWhitelistedIPs", func(t *testing.T) {
		mockRepo := &MockWhitelistedIPRepository{}
		svc := service.NewWhitelistService(mockRepo)
		ctx := context.Background()
		
		mockRepo.On("FindAll", ctx).Return([]models.WhitelistedIP{}, nil)
		
		result, err := svc.GetAllWhitelistedIPs(ctx)
		
		assert.NoError(t, err)
		assert.Empty(t, result)
		mockRepo.AssertExpectations(t)
	})
}

func TestWhitelistService_GetWhitelistedIPByIP(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockWhitelistedIPRepository{}
		svc := service.NewWhitelistService(mockRepo)
		ctx := context.Background()
		
		expected := &models.WhitelistedIP{
			ID:        1,
			IPAddress: "192.168.1.1",
			Reason:    "Internal network",
			AddedBy:   1,
		}
		
		mockRepo.On("FindByIP", ctx, "192.168.1.1").Return(expected, nil)
		
		result, err := svc.GetWhitelistedIPByIP(ctx, "192.168.1.1")
		
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("EmptyIP", func(t *testing.T) {
		mockRepo := &MockWhitelistedIPRepository{}
		svc := service.NewWhitelistService(mockRepo)
		ctx := context.Background()
		
		result, err := svc.GetWhitelistedIPByIP(ctx, "")
		
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "IP address cannot be empty")
		mockRepo.AssertNotCalled(t, "FindByIP")
	})
	
	t.Run("NotFound", func(t *testing.T) {
		mockRepo := &MockWhitelistedIPRepository{}
		svc := service.NewWhitelistService(mockRepo)
		ctx := context.Background()
		
		mockRepo.On("FindByIP", ctx, "192.168.99.99").Return((*models.WhitelistedIP)(nil), nil)
		
		result, err := svc.GetWhitelistedIPByIP(ctx, "192.168.99.99")
		
		assert.NoError(t, err)
		assert.Nil(t, result)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockWhitelistedIPRepository{}
		svc := service.NewWhitelistService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("FindByIP", ctx, "192.168.1.1").Return((*models.WhitelistedIP)(nil), expectedErr)
		
		result, err := svc.GetWhitelistedIPByIP(ctx, "192.168.1.1")
		
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
}

func TestWhitelistService_IsIPWhitelisted(t *testing.T) {
	t.Run("Success_Whitelisted", func(t *testing.T) {
		mockRepo := &MockWhitelistedIPRepository{}
		svc := service.NewWhitelistService(mockRepo)
		ctx := context.Background()
		
		mockRepo.On("IsWhitelisted", ctx, "192.168.1.1").Return(true, nil)
		
		isWhitelisted, err := svc.IsIPWhitelisted(ctx, "192.168.1.1")
		
		assert.NoError(t, err)
		assert.True(t, isWhitelisted)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("Success_NotWhitelisted", func(t *testing.T) {
		mockRepo := &MockWhitelistedIPRepository{}
		svc := service.NewWhitelistService(mockRepo)
		ctx := context.Background()
		
		mockRepo.On("IsWhitelisted", ctx, "192.168.99.99").Return(false, nil)
		
		isWhitelisted, err := svc.IsIPWhitelisted(ctx, "192.168.99.99")
		
		assert.NoError(t, err)
		assert.False(t, isWhitelisted)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("EmptyIP", func(t *testing.T) {
		mockRepo := &MockWhitelistedIPRepository{}
		svc := service.NewWhitelistService(mockRepo)
		ctx := context.Background()
		
		isWhitelisted, err := svc.IsIPWhitelisted(ctx, "")
		
		assert.Error(t, err)
		assert.False(t, isWhitelisted)
		assert.Contains(t, err.Error(), "IP address cannot be empty")
		mockRepo.AssertNotCalled(t, "IsWhitelisted")
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockWhitelistedIPRepository{}
		svc := service.NewWhitelistService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("IsWhitelisted", ctx, "192.168.1.1").Return(false, expectedErr)
		
		isWhitelisted, err := svc.IsIPWhitelisted(ctx, "192.168.1.1")
		
		assert.Error(t, err)
		assert.False(t, isWhitelisted)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
}

func TestWhitelistService_GetWhitelistedIPsCount(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockWhitelistedIPRepository{}
		svc := service.NewWhitelistService(mockRepo)
		ctx := context.Background()
		
		var expectedCount int64 = 10
		mockRepo.On("Count", ctx).Return(expectedCount, nil)
		
		count, err := svc.GetWhitelistedIPsCount(ctx)
		
		assert.NoError(t, err)
		assert.Equal(t, expectedCount, count)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockWhitelistedIPRepository{}
		svc := service.NewWhitelistService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("Count", ctx).Return(int64(0), expectedErr)
		
		count, err := svc.GetWhitelistedIPsCount(ctx)
		
		assert.Error(t, err)
		assert.Zero(t, count)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
}

func TestWhitelistService_GetWhitelistedIPsPaginated(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockWhitelistedIPRepository{}
		svc := service.NewWhitelistService(mockRepo)
		ctx := context.Background()
		
		expected := []models.WhitelistedIP{
			{ID: 1, IPAddress: "192.168.1.1", Reason: "Internal"},
			{ID: 2, IPAddress: "10.0.0.1", Reason: "VPN"},
		}
		var expectedTotal int64 = 50
		
		mockRepo.On("FindPaginated", ctx, 0, 10).Return(expected, expectedTotal, nil)
		
		result, total, err := svc.GetWhitelistedIPsPaginated(ctx, 0, 10)
		
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
		assert.Equal(t, expectedTotal, total)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockWhitelistedIPRepository{}
		svc := service.NewWhitelistService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("FindPaginated", ctx, 0, 10).Return([]models.WhitelistedIP{}, int64(0), expectedErr)
		
		result, total, err := svc.GetWhitelistedIPsPaginated(ctx, 0, 10)
		
		assert.Error(t, err)
		assert.Empty(t, result)
		assert.Zero(t, total)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
}

func TestWhitelistService_AddToWhitelist(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockWhitelistedIPRepository{}
		svc := service.NewWhitelistService(mockRepo)
		ctx := context.Background()
		
		whitelistedIP := &models.WhitelistedIP{
			IPAddress: "192.168.1.100",
			Reason:    "Test server",
			AddedBy:   1,
		}
		
		mockRepo.On("Create", ctx, whitelistedIP).Return(nil)
		
		err := svc.AddToWhitelist(ctx, whitelistedIP)
		
		assert.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("NilWhitelistedIP", func(t *testing.T) {
		mockRepo := &MockWhitelistedIPRepository{}
		svc := service.NewWhitelistService(mockRepo)
		ctx := context.Background()
		
		err := svc.AddToWhitelist(ctx, nil)
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "whitelisted IP cannot be nil")
		mockRepo.AssertNotCalled(t, "Create")
	})
	
	t.Run("EmptyIP", func(t *testing.T) {
		mockRepo := &MockWhitelistedIPRepository{}
		svc := service.NewWhitelistService(mockRepo)
		ctx := context.Background()
		
		whitelistedIP := &models.WhitelistedIP{
			Reason:  "Test",
			AddedBy: 1,
		}
		
		err := svc.AddToWhitelist(ctx, whitelistedIP)
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "IP address cannot be empty")
		mockRepo.AssertNotCalled(t, "Create")
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockWhitelistedIPRepository{}
		svc := service.NewWhitelistService(mockRepo)
		ctx := context.Background()
		
		whitelistedIP := &models.WhitelistedIP{
			IPAddress: "192.168.1.1",
			Reason:    "Test",
			AddedBy:   1,
		}
		
		expectedErr := errors.New("database error")
		mockRepo.On("Create", ctx, whitelistedIP).Return(expectedErr)
		
		err := svc.AddToWhitelist(ctx, whitelistedIP)
		
		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
}

func TestWhitelistService_UpdateWhitelistedIP(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockWhitelistedIPRepository{}
		svc := service.NewWhitelistService(mockRepo)
		ctx := context.Background()
		
		whitelistedIP := &models.WhitelistedIP{
			ID:        1,
			IPAddress: "192.168.1.1",
			Reason:    "Updated reason",
			AddedBy:   1,
		}
		
		mockRepo.On("Update", ctx, whitelistedIP).Return(nil)
		
		err := svc.UpdateWhitelistedIP(ctx, whitelistedIP)
		
		assert.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("NilWhitelistedIP", func(t *testing.T) {
		mockRepo := &MockWhitelistedIPRepository{}
		svc := service.NewWhitelistService(mockRepo)
		ctx := context.Background()
		
		err := svc.UpdateWhitelistedIP(ctx, nil)
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "whitelisted IP cannot be nil")
		mockRepo.AssertNotCalled(t, "Update")
	})
	
	t.Run("EmptyIP", func(t *testing.T) {
		mockRepo := &MockWhitelistedIPRepository{}
		svc := service.NewWhitelistService(mockRepo)
		ctx := context.Background()
		
		whitelistedIP := &models.WhitelistedIP{
			ID:   1,
			Reason: "Test",
		}
		
		err := svc.UpdateWhitelistedIP(ctx, whitelistedIP)
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "IP address cannot be empty")
		mockRepo.AssertNotCalled(t, "Update")
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockWhitelistedIPRepository{}
		svc := service.NewWhitelistService(mockRepo)
		ctx := context.Background()
		
		whitelistedIP := &models.WhitelistedIP{
			ID:        1,
			IPAddress: "192.168.1.1",
			Reason:    "Updated",
		}
		
		expectedErr := errors.New("database error")
		mockRepo.On("Update", ctx, whitelistedIP).Return(expectedErr)
		
		err := svc.UpdateWhitelistedIP(ctx, whitelistedIP)
		
		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("PartialUpdate", func(t *testing.T) {
		mockRepo := &MockWhitelistedIPRepository{}
		svc := service.NewWhitelistService(mockRepo)
		ctx := context.Background()
		
		whitelistedIP := &models.WhitelistedIP{
			ID:   1,
			IPAddress: "192.168.1.1",
			// Solo il campo Reason viene aggiornato
		}
		
		mockRepo.On("Update", ctx, whitelistedIP).Return(nil)
		
		err := svc.UpdateWhitelistedIP(ctx, whitelistedIP)
		
		assert.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})
}

func TestWhitelistService_RemoveFromWhitelist(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockWhitelistedIPRepository{}
		svc := service.NewWhitelistService(mockRepo)
		ctx := context.Background()
		
		mockRepo.On("Delete", ctx, uint(1)).Return(nil)
		
		err := svc.RemoveFromWhitelist(ctx, 1)
		
		assert.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("ZeroID", func(t *testing.T) {
		mockRepo := &MockWhitelistedIPRepository{}
		svc := service.NewWhitelistService(mockRepo)
		ctx := context.Background()
		
		err := svc.RemoveFromWhitelist(ctx, 0)
		
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "whitelisted IP ID must be set")
		mockRepo.AssertNotCalled(t, "Delete")
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockWhitelistedIPRepository{}
		svc := service.NewWhitelistService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("Delete", ctx, uint(1)).Return(expectedErr)
		
		err := svc.RemoveFromWhitelist(ctx, 1)
		
		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
}

func TestWhitelistService_RestoreFromWhitelist(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockRepo := &MockWhitelistedIPRepository{}
		svc := service.NewWhitelistService(mockRepo)
		ctx := context.Background()
		
		expected := &models.WhitelistedIP{
			ID:        1,
			IPAddress: "192.168.1.1",
			Reason:    "Restored entry",
			AddedBy:   1,
		}
		
		mockRepo.On("Restore", ctx, "192.168.1.1").Return(expected, nil)
		
		result, err := svc.RestoreFromWhitelist(ctx, "192.168.1.1")
		
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("EmptyIP", func(t *testing.T) {
		mockRepo := &MockWhitelistedIPRepository{}
		svc := service.NewWhitelistService(mockRepo)
		ctx := context.Background()
		
		result, err := svc.RestoreFromWhitelist(ctx, "")
		
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "IP address cannot be empty")
		mockRepo.AssertNotCalled(t, "Restore")
	})
	
	t.Run("NotFound", func(t *testing.T) {
		mockRepo := &MockWhitelistedIPRepository{}
		svc := service.NewWhitelistService(mockRepo)
		ctx := context.Background()
		
		// Restore restituisce nil, nil quando non trova l'IP
		mockRepo.On("Restore", ctx, "192.168.99.99").Return((*models.WhitelistedIP)(nil), nil)
		
		result, err := svc.RestoreFromWhitelist(ctx, "192.168.99.99")
		
		assert.NoError(t, err)
		assert.Nil(t, result)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockWhitelistedIPRepository{}
		svc := service.NewWhitelistService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("Restore", ctx, "192.168.1.1").Return((*models.WhitelistedIP)(nil), expectedErr)
		
		result, err := svc.RestoreFromWhitelist(ctx, "192.168.1.1")
		
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
}

func TestWhitelistService_CheckWhitelistedIPExists(t *testing.T) {
	t.Run("Success_Found", func(t *testing.T) {
		mockRepo := &MockWhitelistedIPRepository{}
		svc := service.NewWhitelistService(mockRepo)
		ctx := context.Background()
		
		expected := &models.WhitelistedIP{
			ID:        1,
			IPAddress: "192.168.1.1",
			Reason:    "Test",
			AddedBy:   1,
		}
		
		mockRepo.On("ExistsSoftDeleted", ctx, "192.168.1.1").Return(expected, nil)
		
		result, err := svc.CheckWhitelistedIPExists(ctx, "192.168.1.1")
		
		assert.NoError(t, err)
		assert.Equal(t, expected, result)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("Success_NotFound", func(t *testing.T) {
		mockRepo := &MockWhitelistedIPRepository{}
		svc := service.NewWhitelistService(mockRepo)
		ctx := context.Background()
		
		mockRepo.On("ExistsSoftDeleted", ctx, "192.168.99.99").Return((*models.WhitelistedIP)(nil), nil)
		
		result, err := svc.CheckWhitelistedIPExists(ctx, "192.168.99.99")
		
		assert.NoError(t, err)
		assert.Nil(t, result)
		mockRepo.AssertExpectations(t)
	})
	
	t.Run("EmptyIP", func(t *testing.T) {
		mockRepo := &MockWhitelistedIPRepository{}
		svc := service.NewWhitelistService(mockRepo)
		ctx := context.Background()
		
		result, err := svc.CheckWhitelistedIPExists(ctx, "")
		
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "IP address cannot be empty")
		mockRepo.AssertNotCalled(t, "ExistsSoftDeleted")
	})
	
	t.Run("RepositoryError", func(t *testing.T) {
		mockRepo := &MockWhitelistedIPRepository{}
		svc := service.NewWhitelistService(mockRepo)
		ctx := context.Background()
		
		expectedErr := errors.New("database error")
		mockRepo.On("ExistsSoftDeleted", ctx, "192.168.1.1").Return((*models.WhitelistedIP)(nil), expectedErr)
		
		result, err := svc.CheckWhitelistedIPExists(ctx, "192.168.1.1")
		
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Equal(t, expectedErr, err)
		mockRepo.AssertExpectations(t)
	})
}