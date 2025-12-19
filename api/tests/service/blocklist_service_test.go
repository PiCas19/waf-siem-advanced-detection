// tests/service/blocklist_service_test.go
package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/logger"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/service"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// Inizializza il logger prima di tutti i test
func init() {
	// Inizializza il logger per i test
	logger.Log = logrus.New()
	logger.Log.SetLevel(logrus.ErrorLevel) // Imposta livello basso per ridurre rumore nei test
}

// Helper per creare un puntatore a time.Time
func timePtr(t time.Time) *time.Time {
	return &t
}

func TestBlocklistService_GetAllBlockedIPs(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockBlockedRepo := new(MockBlockedIPRepository)
		mockLogRepo := new(MockLogRepository)
		service := service.NewBlocklistService(mockBlockedRepo, mockLogRepo)

		expectedIPs := []models.BlockedIP{
			{ID: 1, IPAddress: "192.168.1.1", Description: "Malicious activity", Permanent: true},
			{ID: 2, IPAddress: "10.0.0.1", Description: "Brute force attack", Permanent: false},
		}

		ctx := context.Background()
		mockBlockedRepo.On("FindAll", ctx).Return(expectedIPs, nil)

		ips, err := service.GetAllBlockedIPs(ctx)

		assert.NoError(t, err)
		assert.Equal(t, expectedIPs, ips)
		mockBlockedRepo.AssertExpectations(t)
	})

	t.Run("repository error", func(t *testing.T) {
		mockBlockedRepo := new(MockBlockedIPRepository)
		mockLogRepo := new(MockLogRepository)
		service := service.NewBlocklistService(mockBlockedRepo, mockLogRepo)

		ctx := context.Background()
		mockBlockedRepo.On("FindAll", ctx).Return([]models.BlockedIP{}, errors.New("database error"))

		ips, err := service.GetAllBlockedIPs(ctx)

		assert.Error(t, err)
		assert.Empty(t, ips)
		mockBlockedRepo.AssertExpectations(t)
	})
}

func TestBlocklistService_GetBlockedIPByIP(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockBlockedRepo := new(MockBlockedIPRepository)
		mockLogRepo := new(MockLogRepository)
		service := service.NewBlocklistService(mockBlockedRepo, mockLogRepo)

		expectedIP := &models.BlockedIP{
			ID:          1,
			IPAddress:   "192.168.1.1",
			Description: "Malicious activity",
			Permanent:   true,
		}

		ctx := context.Background()
		mockBlockedRepo.On("FindByIP", ctx, "192.168.1.1").Return(expectedIP, nil)

		ip, err := service.GetBlockedIPByIP(ctx, "192.168.1.1")

		assert.NoError(t, err)
		assert.Equal(t, expectedIP, ip)
		mockBlockedRepo.AssertExpectations(t)
	})

	t.Run("empty IP address", func(t *testing.T) {
		mockBlockedRepo := new(MockBlockedIPRepository)
		mockLogRepo := new(MockLogRepository)
		service := service.NewBlocklistService(mockBlockedRepo, mockLogRepo)

		ctx := context.Background()
		ip, err := service.GetBlockedIPByIP(ctx, "")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "IP address cannot be empty")
		assert.Nil(t, ip)
		mockBlockedRepo.AssertNotCalled(t, "FindByIP")
	})

	t.Run("IP not found", func(t *testing.T) {
		mockBlockedRepo := new(MockBlockedIPRepository)
		mockLogRepo := new(MockLogRepository)
		service := service.NewBlocklistService(mockBlockedRepo, mockLogRepo)

		ctx := context.Background()
		mockBlockedRepo.On("FindByIP", ctx, "192.168.1.1").Return(nil, errors.New("not found"))

		ip, err := service.GetBlockedIPByIP(ctx, "192.168.1.1")

		assert.Error(t, err)
		assert.Nil(t, ip)
		mockBlockedRepo.AssertExpectations(t)
	})
}

func TestBlocklistService_GetActiveBlockedIPs(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockBlockedRepo := new(MockBlockedIPRepository)
		mockLogRepo := new(MockLogRepository)
		service := service.NewBlocklistService(mockBlockedRepo, mockLogRepo)

		expiresAt := time.Now().Add(24 * time.Hour)
		expectedIPs := []models.BlockedIP{
			{ID: 1, IPAddress: "192.168.1.1", Permanent: true},
			{ID: 3, IPAddress: "10.0.0.3", Permanent: false, ExpiresAt: &expiresAt},
		}

		ctx := context.Background()
		mockBlockedRepo.On("FindActive", ctx).Return(expectedIPs, nil)

		ips, err := service.GetActiveBlockedIPs(ctx)

		assert.NoError(t, err)
		assert.Equal(t, expectedIPs, ips)
		mockBlockedRepo.AssertExpectations(t)
	})

	t.Run("repository error", func(t *testing.T) {
		mockBlockedRepo := new(MockBlockedIPRepository)
		mockLogRepo := new(MockLogRepository)
		service := service.NewBlocklistService(mockBlockedRepo, mockLogRepo)

		ctx := context.Background()
		mockBlockedRepo.On("FindActive", ctx).Return([]models.BlockedIP{}, errors.New("database error"))

		ips, err := service.GetActiveBlockedIPs(ctx)

		assert.Error(t, err)
		assert.Empty(t, ips)
		mockBlockedRepo.AssertExpectations(t)
	})
}

func TestBlocklistService_IsIPBlocked(t *testing.T) {
	t.Run("IP is blocked", func(t *testing.T) {
		mockBlockedRepo := new(MockBlockedIPRepository)
		mockLogRepo := new(MockLogRepository)
		service := service.NewBlocklistService(mockBlockedRepo, mockLogRepo)

		ctx := context.Background()
		mockBlockedRepo.On("IsBlocked", ctx, "192.168.1.1").Return(true, nil)

		isBlocked, err := service.IsIPBlocked(ctx, "192.168.1.1")

		assert.NoError(t, err)
		assert.True(t, isBlocked)
		mockBlockedRepo.AssertExpectations(t)
	})

	t.Run("IP is not blocked", func(t *testing.T) {
		mockBlockedRepo := new(MockBlockedIPRepository)
		mockLogRepo := new(MockLogRepository)
		service := service.NewBlocklistService(mockBlockedRepo, mockLogRepo)

		ctx := context.Background()
		mockBlockedRepo.On("IsBlocked", ctx, "192.168.1.2").Return(false, nil)

		isBlocked, err := service.IsIPBlocked(ctx, "192.168.1.2")

		assert.NoError(t, err)
		assert.False(t, isBlocked)
		mockBlockedRepo.AssertExpectations(t)
	})

	t.Run("empty IP address", func(t *testing.T) {
		mockBlockedRepo := new(MockBlockedIPRepository)
		mockLogRepo := new(MockLogRepository)
		service := service.NewBlocklistService(mockBlockedRepo, mockLogRepo)

		ctx := context.Background()
		isBlocked, err := service.IsIPBlocked(ctx, "")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "IP address cannot be empty")
		assert.False(t, isBlocked)
		mockBlockedRepo.AssertNotCalled(t, "IsBlocked")
	})

	t.Run("repository error", func(t *testing.T) {
		mockBlockedRepo := new(MockBlockedIPRepository)
		mockLogRepo := new(MockLogRepository)
		service := service.NewBlocklistService(mockBlockedRepo, mockLogRepo)

		ctx := context.Background()
		mockBlockedRepo.On("IsBlocked", ctx, "192.168.1.1").Return(false, errors.New("database error"))

		isBlocked, err := service.IsIPBlocked(ctx, "192.168.1.1")

		assert.Error(t, err)
		assert.False(t, isBlocked)
		mockBlockedRepo.AssertExpectations(t)
	})
}

func TestBlocklistService_GetBlockedIPsCount(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockBlockedRepo := new(MockBlockedIPRepository)
		mockLogRepo := new(MockLogRepository)
		service := service.NewBlocklistService(mockBlockedRepo, mockLogRepo)

		ctx := context.Background()
		mockBlockedRepo.On("Count", ctx).Return(int64(150), nil)

		count, err := service.GetBlockedIPsCount(ctx)

		assert.NoError(t, err)
		assert.Equal(t, int64(150), count)
		mockBlockedRepo.AssertExpectations(t)
	})

	t.Run("repository error", func(t *testing.T) {
		mockBlockedRepo := new(MockBlockedIPRepository)
		mockLogRepo := new(MockLogRepository)
		service := service.NewBlocklistService(mockBlockedRepo, mockLogRepo)

		ctx := context.Background()
		mockBlockedRepo.On("Count", ctx).Return(int64(0), errors.New("database error"))

		count, err := service.GetBlockedIPsCount(ctx)

		assert.Error(t, err)
		assert.Equal(t, int64(0), count)
		mockBlockedRepo.AssertExpectations(t)
	})
}

func TestBlocklistService_GetBlockedIPsPaginated(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockBlockedRepo := new(MockBlockedIPRepository)
		mockLogRepo := new(MockLogRepository)
		service := service.NewBlocklistService(mockBlockedRepo, mockLogRepo)

		expectedIPs := []models.BlockedIP{
			{ID: 1, IPAddress: "192.168.1.1"},
			{ID: 2, IPAddress: "10.0.0.1"},
		}

		ctx := context.Background()
		mockBlockedRepo.On("FindPaginated", ctx, 0, 10).Return(expectedIPs, int64(150), nil)

		ips, total, err := service.GetBlockedIPsPaginated(ctx, 0, 10)

		assert.NoError(t, err)
		assert.Equal(t, expectedIPs, ips)
		assert.Equal(t, int64(150), total)
		mockBlockedRepo.AssertExpectations(t)
	})

	t.Run("second page", func(t *testing.T) {
		mockBlockedRepo := new(MockBlockedIPRepository)
		mockLogRepo := new(MockLogRepository)
		service := service.NewBlocklistService(mockBlockedRepo, mockLogRepo)

		ctx := context.Background()
		mockBlockedRepo.On("FindPaginated", ctx, 10, 10).Return([]models.BlockedIP{}, int64(150), nil)

		ips, total, err := service.GetBlockedIPsPaginated(ctx, 10, 10)

		assert.NoError(t, err)
		assert.Empty(t, ips)
		assert.Equal(t, int64(150), total)
		mockBlockedRepo.AssertExpectations(t)
	})

	t.Run("repository error", func(t *testing.T) {
		mockBlockedRepo := new(MockBlockedIPRepository)
		mockLogRepo := new(MockLogRepository)
		service := service.NewBlocklistService(mockBlockedRepo, mockLogRepo)

		ctx := context.Background()
		mockBlockedRepo.On("FindPaginated", ctx, 0, 10).Return([]models.BlockedIP{}, int64(0), errors.New("database error"))

		ips, total, err := service.GetBlockedIPsPaginated(ctx, 0, 10)

		assert.Error(t, err)
		assert.Empty(t, ips)
		assert.Equal(t, int64(0), total)
		mockBlockedRepo.AssertExpectations(t)
	})
}

func TestBlocklistService_BlockIP(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockBlockedRepo := new(MockBlockedIPRepository)
		mockLogRepo := new(MockLogRepository)
		service := service.NewBlocklistService(mockBlockedRepo, mockLogRepo)

		blockedIP := &models.BlockedIP{
			IPAddress:   "192.168.1.1",
			Description: "Malicious activity",
			Permanent:   true,
		}

		ctx := context.Background()
		mockBlockedRepo.On("Create", ctx, blockedIP).Return(nil)

		err := service.BlockIP(ctx, blockedIP)

		assert.NoError(t, err)
		mockBlockedRepo.AssertExpectations(t)
	})

	t.Run("empty IP address", func(t *testing.T) {
		mockBlockedRepo := new(MockBlockedIPRepository)
		mockLogRepo := new(MockLogRepository)
		service := service.NewBlocklistService(mockBlockedRepo, mockLogRepo)

		blockedIP := &models.BlockedIP{
			Description: "Malicious activity",
			Permanent:   true,
		}

		ctx := context.Background()
		err := service.BlockIP(ctx, blockedIP)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "IP address cannot be empty")
		mockBlockedRepo.AssertNotCalled(t, "Create")
	})

	t.Run("repository error", func(t *testing.T) {
		mockBlockedRepo := new(MockBlockedIPRepository)
		mockLogRepo := new(MockLogRepository)
		service := service.NewBlocklistService(mockBlockedRepo, mockLogRepo)

		blockedIP := &models.BlockedIP{
			IPAddress:   "192.168.1.1",
			Description: "Malicious activity",
			Permanent:   true,
		}

		ctx := context.Background()
		mockBlockedRepo.On("Create", ctx, blockedIP).Return(errors.New("database error"))

		err := service.BlockIP(ctx, blockedIP)

		assert.Error(t, err)
		mockBlockedRepo.AssertExpectations(t)
	})
}

func TestBlocklistService_UpdateBlockedIP(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockBlockedRepo := new(MockBlockedIPRepository)
		mockLogRepo := new(MockLogRepository)
		service := service.NewBlocklistService(mockBlockedRepo, mockLogRepo)

		expiresAt := time.Now().Add(24 * time.Hour)
		blockedIP := &models.BlockedIP{
			ID:          1,
			IPAddress:   "192.168.1.1",
			Description: "Updated description",
			Permanent:   false,
			ExpiresAt:   &expiresAt,
		}

		ctx := context.Background()
		mockBlockedRepo.On("Update", ctx, blockedIP).Return(nil)

		err := service.UpdateBlockedIP(ctx, blockedIP)

		assert.NoError(t, err)
		mockBlockedRepo.AssertExpectations(t)
	})

	t.Run("nil blocked IP", func(t *testing.T) {
		mockBlockedRepo := new(MockBlockedIPRepository)
		mockLogRepo := new(MockLogRepository)
		service := service.NewBlocklistService(mockBlockedRepo, mockLogRepo)

		ctx := context.Background()
		err := service.UpdateBlockedIP(ctx, nil)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "blocked IP cannot be nil")
		mockBlockedRepo.AssertNotCalled(t, "Update")
	})

	t.Run("empty IP address", func(t *testing.T) {
		mockBlockedRepo := new(MockBlockedIPRepository)
		mockLogRepo := new(MockLogRepository)
		service := service.NewBlocklistService(mockBlockedRepo, mockLogRepo)

		blockedIP := &models.BlockedIP{
			ID:          1,
			Description: "Updated description",
		}

		ctx := context.Background()
		err := service.UpdateBlockedIP(ctx, blockedIP)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "IP address cannot be empty")
		mockBlockedRepo.AssertNotCalled(t, "Update")
	})

	t.Run("repository error", func(t *testing.T) {
		mockBlockedRepo := new(MockBlockedIPRepository)
		mockLogRepo := new(MockLogRepository)
		service := service.NewBlocklistService(mockBlockedRepo, mockLogRepo)

		blockedIP := &models.BlockedIP{
			ID:          1,
			IPAddress:   "192.168.1.1",
			Description: "Updated description",
			Permanent:   false,
		}

		ctx := context.Background()
		mockBlockedRepo.On("Update", ctx, blockedIP).Return(errors.New("database error"))

		err := service.UpdateBlockedIP(ctx, blockedIP)

		assert.Error(t, err)
		mockBlockedRepo.AssertExpectations(t)
	})
}

func TestBlocklistService_UnblockIP(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockBlockedRepo := new(MockBlockedIPRepository)
		mockLogRepo := new(MockLogRepository)
		service := service.NewBlocklistService(mockBlockedRepo, mockLogRepo)

		ctx := context.Background()
		mockBlockedRepo.On("Delete", ctx, "192.168.1.1").Return(nil)

		err := service.UnblockIP(ctx, "192.168.1.1")

		assert.NoError(t, err)
		mockBlockedRepo.AssertExpectations(t)
	})

	t.Run("empty IP address", func(t *testing.T) {
		mockBlockedRepo := new(MockBlockedIPRepository)
		mockLogRepo := new(MockLogRepository)
		service := service.NewBlocklistService(mockBlockedRepo, mockLogRepo)

		ctx := context.Background()
		err := service.UnblockIP(ctx, "")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "IP address cannot be empty")
		mockBlockedRepo.AssertNotCalled(t, "Delete")
	})

	t.Run("repository error", func(t *testing.T) {
		mockBlockedRepo := new(MockBlockedIPRepository)
		mockLogRepo := new(MockLogRepository)
		service := service.NewBlocklistService(mockBlockedRepo, mockLogRepo)

		ctx := context.Background()
		mockBlockedRepo.On("Delete", ctx, "192.168.1.1").Return(errors.New("database error"))

		err := service.UnblockIP(ctx, "192.168.1.1")

		assert.Error(t, err)
		mockBlockedRepo.AssertExpectations(t)
	})
}

func TestBlocklistService_BlockIPWithLogUpdate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockBlockedRepo := new(MockBlockedIPRepository)
		mockLogRepo := new(MockLogRepository)
		service := service.NewBlocklistService(mockBlockedRepo, mockLogRepo)

		blockedIP := &models.BlockedIP{
			IPAddress:   "192.168.1.1",
			Description: "SQL injection attempt",
			Permanent:   true,
		}

		ctx := context.Background()
		mockBlockedRepo.On("Create", ctx, blockedIP).Return(nil)
		
		expectedUpdates := map[string]interface{}{
			"blocked":   true,
			"blocked_by": "manual",
		}
		mockLogRepo.On("UpdateByIPAndDescription", ctx, "192.168.1.1", "SQL injection attempt", expectedUpdates).Return(nil)

		err := service.BlockIPWithLogUpdate(ctx, blockedIP)

		assert.NoError(t, err)
		mockBlockedRepo.AssertExpectations(t)
		mockLogRepo.AssertExpectations(t)
	})

	t.Run("nil blocked IP", func(t *testing.T) {
		mockBlockedRepo := new(MockBlockedIPRepository)
		mockLogRepo := new(MockLogRepository)
		service := service.NewBlocklistService(mockBlockedRepo, mockLogRepo)

		ctx := context.Background()
		err := service.BlockIPWithLogUpdate(ctx, nil)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "blocked IP cannot be nil")
		mockBlockedRepo.AssertNotCalled(t, "Create")
		mockLogRepo.AssertNotCalled(t, "UpdateByIPAndDescription")
	})

	t.Run("empty IP address", func(t *testing.T) {
		mockBlockedRepo := new(MockBlockedIPRepository)
		mockLogRepo := new(MockLogRepository)
		service := service.NewBlocklistService(mockBlockedRepo, mockLogRepo)

		blockedIP := &models.BlockedIP{
			Description: "SQL injection attempt",
		}

		ctx := context.Background()
		err := service.BlockIPWithLogUpdate(ctx, blockedIP)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "IP address cannot be empty")
		mockBlockedRepo.AssertNotCalled(t, "Create")
		mockLogRepo.AssertNotCalled(t, "UpdateByIPAndDescription")
	})

	t.Run("create fails", func(t *testing.T) {
		mockBlockedRepo := new(MockBlockedIPRepository)
		mockLogRepo := new(MockLogRepository)
		service := service.NewBlocklistService(mockBlockedRepo, mockLogRepo)

		blockedIP := &models.BlockedIP{
			IPAddress:   "192.168.1.1",
			Description: "SQL injection attempt",
			Permanent:   true,
		}

		ctx := context.Background()
		mockBlockedRepo.On("Create", ctx, blockedIP).Return(errors.New("database error"))

		err := service.BlockIPWithLogUpdate(ctx, blockedIP)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create blocked IP")
		mockBlockedRepo.AssertExpectations(t)
		mockLogRepo.AssertNotCalled(t, "UpdateByIPAndDescription")
	})

	t.Run("log update fails", func(t *testing.T) {
		mockBlockedRepo := new(MockBlockedIPRepository)
		mockLogRepo := new(MockLogRepository)
		service := service.NewBlocklistService(mockBlockedRepo, mockLogRepo)

		blockedIP := &models.BlockedIP{
			IPAddress:   "192.168.1.1",
			Description: "SQL injection attempt",
			Permanent:   true,
		}

		ctx := context.Background()
		mockBlockedRepo.On("Create", ctx, blockedIP).Return(nil)
		
		expectedUpdates := map[string]interface{}{
			"blocked":   true,
			"blocked_by": "manual",
		}
		mockLogRepo.On("UpdateByIPAndDescription", ctx, "192.168.1.1", "SQL injection attempt", expectedUpdates).Return(errors.New("log update failed"))

		err := service.BlockIPWithLogUpdate(ctx, blockedIP)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to update logs")
		mockBlockedRepo.AssertExpectations(t)
		mockLogRepo.AssertExpectations(t)
	})
}

func TestBlocklistService_GetBlockedIPByIPAndDescription(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockBlockedRepo := new(MockBlockedIPRepository)
		mockLogRepo := new(MockLogRepository)
		service := service.NewBlocklistService(mockBlockedRepo, mockLogRepo)

		expectedIP := &models.BlockedIP{
			ID:          1,
			IPAddress:   "192.168.1.1",
			Description: "SQL injection",
			Permanent:   true,
		}

		ctx := context.Background()
		mockBlockedRepo.On("FindByIPAndDescription", ctx, "192.168.1.1", "SQL injection").Return(expectedIP, nil)

		ip, err := service.GetBlockedIPByIPAndDescription(ctx, "192.168.1.1", "SQL injection")

		assert.NoError(t, err)
		assert.Equal(t, expectedIP, ip)
		mockBlockedRepo.AssertExpectations(t)
	})

	t.Run("empty IP", func(t *testing.T) {
		mockBlockedRepo := new(MockBlockedIPRepository)
		mockLogRepo := new(MockLogRepository)
		service := service.NewBlocklistService(mockBlockedRepo, mockLogRepo)

		ctx := context.Background()
		ip, err := service.GetBlockedIPByIPAndDescription(ctx, "", "SQL injection")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "IP and description cannot be empty")
		assert.Nil(t, ip)
		mockBlockedRepo.AssertNotCalled(t, "FindByIPAndDescription")
	})

	t.Run("empty description", func(t *testing.T) {
		mockBlockedRepo := new(MockBlockedIPRepository)
		mockLogRepo := new(MockLogRepository)
		service := service.NewBlocklistService(mockBlockedRepo, mockLogRepo)

		ctx := context.Background()
		ip, err := service.GetBlockedIPByIPAndDescription(ctx, "192.168.1.1", "")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "IP and description cannot be empty")
		assert.Nil(t, ip)
		mockBlockedRepo.AssertNotCalled(t, "FindByIPAndDescription")
	})

	t.Run("not found", func(t *testing.T) {
		mockBlockedRepo := new(MockBlockedIPRepository)
		mockLogRepo := new(MockLogRepository)
		service := service.NewBlocklistService(mockBlockedRepo, mockLogRepo)

		ctx := context.Background()
		mockBlockedRepo.On("FindByIPAndDescription", ctx, "192.168.1.1", "SQL injection").Return(nil, errors.New("not found"))

		ip, err := service.GetBlockedIPByIPAndDescription(ctx, "192.168.1.1", "SQL injection")

		assert.Error(t, err)
		assert.Nil(t, ip)
		mockBlockedRepo.AssertExpectations(t)
	})
}

func TestNewBlocklistService(t *testing.T) {
	mockBlockedRepo := new(MockBlockedIPRepository)
	mockLogRepo := new(MockLogRepository)
	
	service := service.NewBlocklistService(mockBlockedRepo, mockLogRepo)

	assert.NotNil(t, service)
	
	// Test che il servizio funzioni chiamando un metodo semplice
	ctx := context.Background()
	mockBlockedRepo.On("Count", ctx).Return(int64(0), nil)
	
	_, err := service.GetBlockedIPsCount(ctx)
	assert.NoError(t, err)
}