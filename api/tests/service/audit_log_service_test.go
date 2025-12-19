package service

import (
	"context"
	"errors"
	"testing"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockAuditLogRepository è un mock del repository per i test
type MockAuditLogRepository struct {
	mock.Mock
}

func (m *MockAuditLogRepository) FindAll(ctx context.Context) ([]models.AuditLog, error) {
	args := m.Called(ctx)
	return args.Get(0).([]models.AuditLog), args.Error(1)
}

func (m *MockAuditLogRepository) FindByUser(ctx context.Context, userID uint) ([]models.AuditLog, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).([]models.AuditLog), args.Error(1)
}

func (m *MockAuditLogRepository) FindByAction(ctx context.Context, action string) ([]models.AuditLog, error) {
	args := m.Called(ctx, action)
	return args.Get(0).([]models.AuditLog), args.Error(1)
}

func (m *MockAuditLogRepository) FindRecent(ctx context.Context, limit int) ([]models.AuditLog, error) {
	args := m.Called(ctx, limit)
	return args.Get(0).([]models.AuditLog), args.Error(1)
}

func (m *MockAuditLogRepository) Count(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockAuditLogRepository) CountByStatus(ctx context.Context, status string) (int64, error) {
	args := m.Called(ctx, status)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockAuditLogRepository) Create(ctx context.Context, auditLog *models.AuditLog) error {
	args := m.Called(ctx, auditLog)
	return args.Error(0)
}

func (m *MockAuditLogRepository) FindPaginated(ctx context.Context, offset, limit int) ([]models.AuditLog, int64, error) {
	args := m.Called(ctx, offset, limit)
	return args.Get(0).([]models.AuditLog), args.Get(1).(int64), args.Error(2)
}

func (m *MockAuditLogRepository) GetActionBreakdown(ctx context.Context) (map[string]int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(map[string]int64), args.Error(1)
}

func TestAuditLogService_GetAllAuditLogs(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		// Setup
		mockRepo := new(MockAuditLogRepository)
		service := service.NewAuditLogService(mockRepo)

		expectedLogs := []models.AuditLog{
			{ID: 1, UserID: 1, Action: "login", Status: "success"},
			{ID: 2, UserID: 2, Action: "logout", Status: "success"},
		}

		ctx := context.Background()
		mockRepo.On("FindAll", ctx).Return(expectedLogs, nil)

		// Execute
		logs, err := service.GetAllAuditLogs(ctx)

		// Verify
		assert.NoError(t, err)
		assert.Equal(t, expectedLogs, logs)
		mockRepo.AssertExpectations(t)
	})

	t.Run("repository error", func(t *testing.T) {
		mockRepo := new(MockAuditLogRepository)
		service := service.NewAuditLogService(mockRepo)

		ctx := context.Background()
		mockRepo.On("FindAll", ctx).Return([]models.AuditLog{}, errors.New("database error"))

		logs, err := service.GetAllAuditLogs(ctx)

		assert.Error(t, err)
		assert.Empty(t, logs)
		mockRepo.AssertExpectations(t)
	})
}

func TestAuditLogService_GetAuditLogsByUser(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockRepo := new(MockAuditLogRepository)
		service := service.NewAuditLogService(mockRepo)

		expectedLogs := []models.AuditLog{
			{ID: 1, UserID: 1, Action: "login", Status: "success"},
			{ID: 3, UserID: 1, Action: "update", Status: "success"},
		}

		ctx := context.Background()
		mockRepo.On("FindByUser", ctx, uint(1)).Return(expectedLogs, nil)

		logs, err := service.GetAuditLogsByUser(ctx, 1)

		assert.NoError(t, err)
		assert.Equal(t, expectedLogs, logs)
		mockRepo.AssertExpectations(t)
	})

	t.Run("invalid user ID", func(t *testing.T) {
		mockRepo := new(MockAuditLogRepository)
		service := service.NewAuditLogService(mockRepo)

		ctx := context.Background()
		logs, err := service.GetAuditLogsByUser(ctx, 0)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "user ID must be set")
		assert.Empty(t, logs)
		mockRepo.AssertNotCalled(t, "FindByUser")
	})

	t.Run("repository error", func(t *testing.T) {
		mockRepo := new(MockAuditLogRepository)
		service := service.NewAuditLogService(mockRepo)

		ctx := context.Background()
		mockRepo.On("FindByUser", ctx, uint(1)).Return([]models.AuditLog{}, errors.New("database error"))

		logs, err := service.GetAuditLogsByUser(ctx, 1)

		assert.Error(t, err)
		assert.Empty(t, logs)
		mockRepo.AssertExpectations(t)
	})
}

func TestAuditLogService_GetAuditLogsByAction(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockRepo := new(MockAuditLogRepository)
		service := service.NewAuditLogService(mockRepo)

		expectedLogs := []models.AuditLog{
			{ID: 1, UserID: 1, Action: "login", Status: "success"},
			{ID: 2, UserID: 2, Action: "login", Status: "failure"},
		}

		ctx := context.Background()
		mockRepo.On("FindByAction", ctx, "login").Return(expectedLogs, nil)

		logs, err := service.GetAuditLogsByAction(ctx, "login")

		assert.NoError(t, err)
		assert.Equal(t, expectedLogs, logs)
		mockRepo.AssertExpectations(t)
	})

	t.Run("empty action", func(t *testing.T) {
		mockRepo := new(MockAuditLogRepository)
		service := service.NewAuditLogService(mockRepo)

		ctx := context.Background()
		logs, err := service.GetAuditLogsByAction(ctx, "")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "action cannot be empty")
		assert.Empty(t, logs)
		mockRepo.AssertNotCalled(t, "FindByAction")
	})

	t.Run("repository error", func(t *testing.T) {
		mockRepo := new(MockAuditLogRepository)
		service := service.NewAuditLogService(mockRepo)

		ctx := context.Background()
		mockRepo.On("FindByAction", ctx, "login").Return([]models.AuditLog{}, errors.New("database error"))

		logs, err := service.GetAuditLogsByAction(ctx, "login")

		assert.Error(t, err)
		assert.Empty(t, logs)
		mockRepo.AssertExpectations(t)
	})
}

func TestAuditLogService_GetRecentAuditLogs(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockRepo := new(MockAuditLogRepository)
		service := service.NewAuditLogService(mockRepo)

		expectedLogs := []models.AuditLog{
			{ID: 1, UserID: 1, Action: "login", Status: "success"},
		}

		ctx := context.Background()
		mockRepo.On("FindRecent", ctx, 100).Return(expectedLogs, nil)

		logs, err := service.GetRecentAuditLogs(ctx, 100)

		assert.NoError(t, err)
		assert.Equal(t, expectedLogs, logs)
		mockRepo.AssertExpectations(t)
	})

	t.Run("invalid limit", func(t *testing.T) {
		mockRepo := new(MockAuditLogRepository)
		service := service.NewAuditLogService(mockRepo)

		testCases := []struct {
			name  string
			limit int
		}{
			{"zero", 0},
			{"negative", -1},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				ctx := context.Background()
				logs, err := service.GetRecentAuditLogs(ctx, tc.limit)

				assert.Error(t, err)
				assert.Contains(t, err.Error(), "limit must be positive")
				assert.Empty(t, logs)
				mockRepo.AssertNotCalled(t, "FindRecent")
			})
		}
	})

	t.Run("repository error", func(t *testing.T) {
		mockRepo := new(MockAuditLogRepository)
		service := service.NewAuditLogService(mockRepo)

		ctx := context.Background()
		mockRepo.On("FindRecent", ctx, 50).Return([]models.AuditLog{}, errors.New("database error"))

		logs, err := service.GetRecentAuditLogs(ctx, 50)

		assert.Error(t, err)
		assert.Empty(t, logs)
		mockRepo.AssertExpectations(t)
	})
}

func TestAuditLogService_GetAuditLogsCount(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockRepo := new(MockAuditLogRepository)
		service := service.NewAuditLogService(mockRepo)

		ctx := context.Background()
		mockRepo.On("Count", ctx).Return(int64(100), nil)

		count, err := service.GetAuditLogsCount(ctx)

		assert.NoError(t, err)
		assert.Equal(t, int64(100), count)
		mockRepo.AssertExpectations(t)
	})

	t.Run("repository error", func(t *testing.T) {
		mockRepo := new(MockAuditLogRepository)
		service := service.NewAuditLogService(mockRepo)

		ctx := context.Background()
		mockRepo.On("Count", ctx).Return(int64(0), errors.New("database error"))

		count, err := service.GetAuditLogsCount(ctx)

		assert.Error(t, err)
		assert.Equal(t, int64(0), count)
		mockRepo.AssertExpectations(t)
	})
}

func TestAuditLogService_GetSuccessfulActionsCount(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockRepo := new(MockAuditLogRepository)
		service := service.NewAuditLogService(mockRepo)

		ctx := context.Background()
		mockRepo.On("CountByStatus", ctx, "success").Return(int64(80), nil)

		count, err := service.GetSuccessfulActionsCount(ctx)

		assert.NoError(t, err)
		assert.Equal(t, int64(80), count)
		mockRepo.AssertExpectations(t)
	})

	t.Run("repository error", func(t *testing.T) {
		mockRepo := new(MockAuditLogRepository)
		service := service.NewAuditLogService(mockRepo)

		ctx := context.Background()
		mockRepo.On("CountByStatus", ctx, "success").Return(int64(0), errors.New("database error"))

		count, err := service.GetSuccessfulActionsCount(ctx)

		assert.Error(t, err)
		assert.Equal(t, int64(0), count)
		mockRepo.AssertExpectations(t)
	})
}

func TestAuditLogService_GetFailedActionsCount(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockRepo := new(MockAuditLogRepository)
		service := service.NewAuditLogService(mockRepo)

		ctx := context.Background()
		mockRepo.On("CountByStatus", ctx, "failure").Return(int64(20), nil)

		count, err := service.GetFailedActionsCount(ctx)

		assert.NoError(t, err)
		assert.Equal(t, int64(20), count)
		mockRepo.AssertExpectations(t)
	})

	t.Run("repository error", func(t *testing.T) {
		mockRepo := new(MockAuditLogRepository)
		service := service.NewAuditLogService(mockRepo)

		ctx := context.Background()
		mockRepo.On("CountByStatus", ctx, "failure").Return(int64(0), errors.New("database error"))

		count, err := service.GetFailedActionsCount(ctx)

		assert.Error(t, err)
		assert.Equal(t, int64(0), count)
		mockRepo.AssertExpectations(t)
	})
}

func TestAuditLogService_CreateAuditLog(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockRepo := new(MockAuditLogRepository)
		service := service.NewAuditLogService(mockRepo)

		auditLog := &models.AuditLog{
			UserID:  1,
			Action:  "login",
			Status:  "success",
			Details: "User logged in successfully",
		}

		ctx := context.Background()
		mockRepo.On("Create", ctx, auditLog).Return(nil)

		err := service.CreateAuditLog(ctx, auditLog)

		assert.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})

	t.Run("nil audit log", func(t *testing.T) {
		mockRepo := new(MockAuditLogRepository)
		service := service.NewAuditLogService(mockRepo)

		ctx := context.Background()
		err := service.CreateAuditLog(ctx, nil)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "audit log cannot be nil")
		mockRepo.AssertNotCalled(t, "Create")
	})

	t.Run("missing user ID", func(t *testing.T) {
		mockRepo := new(MockAuditLogRepository)
		service := service.NewAuditLogService(mockRepo)

		auditLog := &models.AuditLog{
			Action: "login",
			Status: "success",
		}

		ctx := context.Background()
		err := service.CreateAuditLog(ctx, auditLog)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "user ID must be set")
		mockRepo.AssertNotCalled(t, "Create")
	})

	t.Run("missing action", func(t *testing.T) {
		mockRepo := new(MockAuditLogRepository)
		service := service.NewAuditLogService(mockRepo)

		auditLog := &models.AuditLog{
			UserID: 1,
			Status: "success",
		}

		ctx := context.Background()
		err := service.CreateAuditLog(ctx, auditLog)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "action cannot be empty")
		mockRepo.AssertNotCalled(t, "Create")
	})

	t.Run("repository error", func(t *testing.T) {
		mockRepo := new(MockAuditLogRepository)
		service := service.NewAuditLogService(mockRepo)

		auditLog := &models.AuditLog{
			UserID:  1,
			Action:  "login",
			Status:  "success",
			Details: "User logged in",
		}

		ctx := context.Background()
		mockRepo.On("Create", ctx, auditLog).Return(errors.New("database error"))

		err := service.CreateAuditLog(ctx, auditLog)

		assert.Error(t, err)
		mockRepo.AssertExpectations(t)
	})
}

func TestAuditLogService_GetPaginatedAuditLogs(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockRepo := new(MockAuditLogRepository)
		service := service.NewAuditLogService(mockRepo)

		expectedLogs := []models.AuditLog{
			{ID: 1, UserID: 1, Action: "login", Status: "success"},
			{ID: 2, UserID: 2, Action: "logout", Status: "success"},
		}

		ctx := context.Background()
		mockRepo.On("FindPaginated", ctx, 0, 10).Return(expectedLogs, int64(100), nil)

		logs, total, err := service.GetPaginatedAuditLogs(ctx, 1, 10)

		assert.NoError(t, err)
		assert.Equal(t, expectedLogs, logs)
		assert.Equal(t, int64(100), total)
		mockRepo.AssertExpectations(t)
	})

	t.Run("page 2", func(t *testing.T) {
		mockRepo := new(MockAuditLogRepository)
		service := service.NewAuditLogService(mockRepo)

		ctx := context.Background()
		mockRepo.On("FindPaginated", ctx, 10, 10).Return([]models.AuditLog{}, int64(100), nil)

		_, _, err := service.GetPaginatedAuditLogs(ctx, 2, 10)

		assert.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})

	t.Run("invalid page", func(t *testing.T) {
		mockRepo := new(MockAuditLogRepository)
		service := service.NewAuditLogService(mockRepo)

		testCases := []struct {
			name     string
			page     int
			pageSize int
		}{
			{"zero page", 0, 10},
			{"negative page", -1, 10},
			{"zero pageSize", 1, 0},
			{"negative pageSize", 1, -1},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				ctx := context.Background()
				logs, total, err := service.GetPaginatedAuditLogs(ctx, tc.page, tc.pageSize)

				assert.Error(t, err)
				assert.Contains(t, err.Error(), "page and pageSize must be positive")
				assert.Empty(t, logs)
				assert.Equal(t, int64(0), total)
				mockRepo.AssertNotCalled(t, "FindPaginated")
			})
		}
	})

	t.Run("repository error", func(t *testing.T) {
		mockRepo := new(MockAuditLogRepository)
		service := service.NewAuditLogService(mockRepo)

		ctx := context.Background()
		mockRepo.On("FindPaginated", ctx, 0, 10).Return([]models.AuditLog{}, int64(0), errors.New("database error"))

		logs, total, err := service.GetPaginatedAuditLogs(ctx, 1, 10)

		assert.Error(t, err)
		assert.Empty(t, logs)
		assert.Equal(t, int64(0), total)
		mockRepo.AssertExpectations(t)
	})
}

func TestAuditLogService_GetActionBreakdown(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockRepo := new(MockAuditLogRepository)
		service := service.NewAuditLogService(mockRepo)

		expectedBreakdown := map[string]int64{
			"login":  50,
			"logout": 30,
			"update": 20,
		}

		ctx := context.Background()
		mockRepo.On("GetActionBreakdown", ctx).Return(expectedBreakdown, nil)

		breakdown, err := service.GetActionBreakdown(ctx)

		assert.NoError(t, err)
		assert.Equal(t, expectedBreakdown, breakdown)
		mockRepo.AssertExpectations(t)
	})

	t.Run("repository error", func(t *testing.T) {
		mockRepo := new(MockAuditLogRepository)
		service := service.NewAuditLogService(mockRepo)

		ctx := context.Background()
		mockRepo.On("GetActionBreakdown", ctx).Return(map[string]int64{}, errors.New("database error"))

		breakdown, err := service.GetActionBreakdown(ctx)

		assert.Error(t, err)
		assert.Empty(t, breakdown)
		mockRepo.AssertExpectations(t)
	})
}

func TestAuditLogService_LogAction(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockRepo := new(MockAuditLogRepository)
		service := service.NewAuditLogService(mockRepo)

		ctx := context.Background()
		// Il metodo LogAction chiama CreateAuditLog, quindi mockiamo Create
		mockRepo.On("Create", ctx, mock.AnythingOfType("*models.AuditLog")).Run(func(args mock.Arguments) {
			auditLog := args.Get(1).(*models.AuditLog)
			assert.Equal(t, uint(1), auditLog.UserID)
			assert.Equal(t, "login", auditLog.Action)
			assert.Equal(t, "success", auditLog.Status)
			assert.Equal(t, "User logged in", auditLog.Details)
		}).Return(nil)

		err := service.LogAction(ctx, 1, "login", "success", "User logged in")

		assert.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})

	t.Run("invalid parameters", func(t *testing.T) {
		mockRepo := new(MockAuditLogRepository)
		service := service.NewAuditLogService(mockRepo)

		testCases := []struct {
			name    string
			userID  uint
			action  string
			status  string
			details string
		}{
			{"zero user ID", 0, "login", "success", "details"},
			{"empty action", 1, "", "success", "details"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				ctx := context.Background()
				err := service.LogAction(ctx, tc.userID, tc.action, tc.status, tc.details)

				assert.Error(t, err)
				mockRepo.AssertNotCalled(t, "Create")
			})
		}
	})

	t.Run("repository error", func(t *testing.T) {
		mockRepo := new(MockAuditLogRepository)
		service := service.NewAuditLogService(mockRepo)

		ctx := context.Background()
		mockRepo.On("Create", ctx, mock.AnythingOfType("*models.AuditLog")).Return(errors.New("database error"))

		err := service.LogAction(ctx, 1, "login", "success", "details")

		assert.Error(t, err)
		mockRepo.AssertExpectations(t)
	})
}

func TestAuditLogService_LogActionSuccess(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockRepo := new(MockAuditLogRepository)
		service := service.NewAuditLogService(mockRepo)

		ctx := context.Background()
		mockRepo.On("Create", ctx, mock.AnythingOfType("*models.AuditLog")).Run(func(args mock.Arguments) {
			auditLog := args.Get(1).(*models.AuditLog)
			assert.Equal(t, uint(1), auditLog.UserID)
			assert.Equal(t, "login", auditLog.Action)
			assert.Equal(t, "success", auditLog.Status) // Verifica che sia "success"
			assert.Equal(t, "User logged in successfully", auditLog.Details)
		}).Return(nil)

		err := service.LogActionSuccess(ctx, 1, "login", "User logged in successfully")

		assert.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})
}

func TestAuditLogService_LogActionFailure(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockRepo := new(MockAuditLogRepository)
		service := service.NewAuditLogService(mockRepo)

		ctx := context.Background()
		mockRepo.On("Create", ctx, mock.AnythingOfType("*models.AuditLog")).Run(func(args mock.Arguments) {
			auditLog := args.Get(1).(*models.AuditLog)
			assert.Equal(t, uint(1), auditLog.UserID)
			assert.Equal(t, "login", auditLog.Action)
			assert.Equal(t, "failure", auditLog.Status) // Verifica che sia "failure"
			assert.Equal(t, "Invalid credentials", auditLog.Details)
		}).Return(nil)

		err := service.LogActionFailure(ctx, 1, "login", "Invalid credentials")

		assert.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})
}

func TestNewAuditLogService(t *testing.T) {
	mockRepo := new(MockAuditLogRepository)
	service := service.NewAuditLogService(mockRepo)

	assert.NotNil(t, service)
	// Non possiamo verificare il campo privato, ma possiamo testare che il servizio funzioni
	// chiamando un metodo semplice
	ctx := context.Background()
	mockRepo.On("Count", ctx).Return(int64(0), nil)
	
	_, err := service.GetAuditLogsCount(ctx)
	assert.NoError(t, err)
}