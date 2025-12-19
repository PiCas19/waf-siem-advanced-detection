// tests/service/mocks.go
package service

import (
	"context"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/stretchr/testify/mock"
)

// MockFalsePositiveRepository è un mock per FalsePositiveRepository
type MockFalsePositiveRepository struct {
	mock.Mock
}

func (m *MockFalsePositiveRepository) FindAll(ctx context.Context) ([]models.FalsePositive, error) {
	args := m.Called(ctx)
	return args.Get(0).([]models.FalsePositive), args.Error(1)
}

func (m *MockFalsePositiveRepository) FindPaginated(ctx context.Context, offset, limit int) ([]models.FalsePositive, int64, error) {
	args := m.Called(ctx, offset, limit)
	return args.Get(0).([]models.FalsePositive), args.Get(1).(int64), args.Error(2)
}

func (m *MockFalsePositiveRepository) FindByID(ctx context.Context, id uint) (*models.FalsePositive, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.FalsePositive), args.Error(1)
}

func (m *MockFalsePositiveRepository) FindByIP(ctx context.Context, ip string) ([]models.FalsePositive, error) {
	args := m.Called(ctx, ip)
	return args.Get(0).([]models.FalsePositive), args.Error(1)
}

func (m *MockFalsePositiveRepository) FindUnresolved(ctx context.Context) ([]models.FalsePositive, error) {
	args := m.Called(ctx)
	return args.Get(0).([]models.FalsePositive), args.Error(1)
}

func (m *MockFalsePositiveRepository) Count(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockFalsePositiveRepository) CountUnresolved(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockFalsePositiveRepository) Create(ctx context.Context, fp *models.FalsePositive) error {
	args := m.Called(ctx, fp)
	return args.Error(0)
}

func (m *MockFalsePositiveRepository) Update(ctx context.Context, fp *models.FalsePositive) error {
	args := m.Called(ctx, fp)
	return args.Error(0)
}

func (m *MockFalsePositiveRepository) Delete(ctx context.Context, id uint) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

// MockLogRepository è un mock per LogRepository
type MockLogRepository struct {
	mock.Mock
}

func (m *MockLogRepository) FindAll(ctx context.Context) ([]models.Log, error) {
	args := m.Called(ctx)
	return args.Get(0).([]models.Log), args.Error(1)
}

func (m *MockLogRepository) FindPaginated(ctx context.Context, offset, limit int) ([]models.Log, int64, error) {
	args := m.Called(ctx, offset, limit)
	return args.Get(0).([]models.Log), args.Get(1).(int64), args.Error(2)
}

func (m *MockLogRepository) FindByID(ctx context.Context, id uint) (*models.Log, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Log), args.Error(1)
}

func (m *MockLogRepository) FindByIP(ctx context.Context, ip string) ([]models.Log, error) {
	args := m.Called(ctx, ip)
	return args.Get(0).([]models.Log), args.Error(1)
}

func (m *MockLogRepository) FindBlocked(ctx context.Context) ([]models.Log, error) {
	args := m.Called(ctx)
	return args.Get(0).([]models.Log), args.Error(1)
}

func (m *MockLogRepository) FindByThreatType(ctx context.Context, threatType string) ([]models.Log, error) {
	args := m.Called(ctx, threatType)
	return args.Get(0).([]models.Log), args.Error(1)
}

func (m *MockLogRepository) FindRecent(ctx context.Context, limit int) ([]models.Log, error) {
	args := m.Called(ctx, limit)
	return args.Get(0).([]models.Log), args.Error(1)
}

func (m *MockLogRepository) Count(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockLogRepository) CountBlocked(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockLogRepository) Create(ctx context.Context, log *models.Log) error {
	args := m.Called(ctx, log)
	return args.Error(0)
}

func (m *MockLogRepository) Update(ctx context.Context, log *models.Log) error {
	args := m.Called(ctx, log)
	return args.Error(0)
}

func (m *MockLogRepository) Delete(ctx context.Context, id uint) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockLogRepository) UpdateByIPAndDescription(ctx context.Context, ip string, description string, updates map[string]interface{}) error {
	args := m.Called(ctx, ip, description, updates)
	return args.Error(0)
}

func (m *MockLogRepository) UpdateDetectedByIPAndDescription(ctx context.Context, ip string, description string, updates map[string]interface{}) error {
	args := m.Called(ctx, ip, description, updates)
	return args.Error(0)
}

func (m *MockLogRepository) DeleteManualBlockLog(ctx context.Context, ip string, description string) error {
	args := m.Called(ctx, ip, description)
	return args.Error(0)
}

func (m *MockLogRepository) CountByType(ctx context.Context, logType string) (int64, error) {
	args := m.Called(ctx, logType)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockLogRepository) GetStatistics(ctx context.Context) (map[string]interface{}, error) {
	args := m.Called(ctx)
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

// MockBlockedIPRepository è un mock del repository per IP bloccati
type MockBlockedIPRepository struct {
	mock.Mock
}

func (m *MockBlockedIPRepository) FindAll(ctx context.Context) ([]models.BlockedIP, error) {
	args := m.Called(ctx)
	return args.Get(0).([]models.BlockedIP), args.Error(1)
}

func (m *MockBlockedIPRepository) FindByIP(ctx context.Context, ip string) (*models.BlockedIP, error) {
	args := m.Called(ctx, ip)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.BlockedIP), args.Error(1)
}

func (m *MockBlockedIPRepository) FindActive(ctx context.Context) ([]models.BlockedIP, error) {
	args := m.Called(ctx)
	return args.Get(0).([]models.BlockedIP), args.Error(1)
}

func (m *MockBlockedIPRepository) IsBlocked(ctx context.Context, ip string) (bool, error) {
	args := m.Called(ctx, ip)
	return args.Bool(0), args.Error(1)
}

func (m *MockBlockedIPRepository) Count(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockBlockedIPRepository) FindPaginated(ctx context.Context, offset, limit int) ([]models.BlockedIP, int64, error) {
	args := m.Called(ctx, offset, limit)
	return args.Get(0).([]models.BlockedIP), args.Get(1).(int64), args.Error(2)
}

func (m *MockBlockedIPRepository) Create(ctx context.Context, blockedIP *models.BlockedIP) error {
	args := m.Called(ctx, blockedIP)
	return args.Error(0)
}

func (m *MockBlockedIPRepository) Update(ctx context.Context, blockedIP *models.BlockedIP) error {
	args := m.Called(ctx, blockedIP)
	return args.Error(0)
}

func (m *MockBlockedIPRepository) Delete(ctx context.Context, ip string) error {
	args := m.Called(ctx, ip)
	return args.Error(0)
}

func (m *MockBlockedIPRepository) FindByIPAndDescription(ctx context.Context, ip string, description string) (*models.BlockedIP, error) {
	args := m.Called(ctx, ip, description)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.BlockedIP), args.Error(1)
}

type MockRuleRepository struct {
	mock.Mock
}

func (m *MockRuleRepository) FindAll(ctx context.Context) ([]models.Rule, error) {
	args := m.Called(ctx)
	return args.Get(0).([]models.Rule), args.Error(1)
}

func (m *MockRuleRepository) FindByID(ctx context.Context, id uint) (*models.Rule, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Rule), args.Error(1)
}

func (m *MockRuleRepository) FindEnabled(ctx context.Context) ([]models.Rule, error) {
	args := m.Called(ctx)
	return args.Get(0).([]models.Rule), args.Error(1)
}

func (m *MockRuleRepository) Create(ctx context.Context, rule *models.Rule) error {
	args := m.Called(ctx, rule)
	return args.Error(0)
}

func (m *MockRuleRepository) Update(ctx context.Context, rule *models.Rule) error {
	args := m.Called(ctx, rule)
	return args.Error(0)
}

func (m *MockRuleRepository) Delete(ctx context.Context, id uint) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockRuleRepository) ToggleEnabled(ctx context.Context, id uint, enabled bool) error {
	args := m.Called(ctx, id, enabled)
	return args.Error(0)
}

func (m *MockRuleRepository) Count(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockRuleRepository) FindByType(ctx context.Context, threatType string) ([]models.Rule, error) {
	args := m.Called(ctx, threatType)
	return args.Get(0).([]models.Rule), args.Error(1)
}

func (m *MockRuleRepository) FindPaginated(ctx context.Context, offset int, limit int) ([]models.Rule, int64, error) {
	args := m.Called(ctx, offset, limit)
	return args.Get(0).([]models.Rule), args.Get(1).(int64), args.Error(2)
}

type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) FindAll(ctx context.Context) ([]models.User, error) {
	args := m.Called(ctx)
	return args.Get(0).([]models.User), args.Error(1)
}

func (m *MockUserRepository) FindByID(ctx context.Context, id uint) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) Create(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) Update(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) Delete(ctx context.Context, id uint) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockUserRepository) Count(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockUserRepository) UpdateRole(ctx context.Context, id uint, role string) error {
	args := m.Called(ctx, id, role)
	return args.Error(0)
}

func (m *MockUserRepository) FindByRole(ctx context.Context, role string) ([]models.User, error) {
	args := m.Called(ctx, role)
	return args.Get(0).([]models.User), args.Error(1)
}

func (m *MockUserRepository) CountByRole(ctx context.Context, role string) (int64, error) {
	args := m.Called(ctx, role)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockUserRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	args := m.Called(ctx, email)
	return args.Bool(0), args.Error(1)
}

func (m *MockUserRepository) FindPaginated(ctx context.Context, offset int, limit int) ([]models.User, int64, error) {
	args := m.Called(ctx, offset, limit)
	return args.Get(0).([]models.User), args.Get(1).(int64), args.Error(2)
}


type MockWhitelistedIPRepository struct {
	mock.Mock
}

func (m *MockWhitelistedIPRepository) FindAll(ctx context.Context) ([]models.WhitelistedIP, error) {
	args := m.Called(ctx)
	return args.Get(0).([]models.WhitelistedIP), args.Error(1)
}

func (m *MockWhitelistedIPRepository) FindByIP(ctx context.Context, ip string) (*models.WhitelistedIP, error) {
	args := m.Called(ctx, ip)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.WhitelistedIP), args.Error(1)
}

func (m *MockWhitelistedIPRepository) Create(ctx context.Context, whitelistedIP *models.WhitelistedIP) error {
	args := m.Called(ctx, whitelistedIP)
	return args.Error(0)
}

func (m *MockWhitelistedIPRepository) Update(ctx context.Context, whitelistedIP *models.WhitelistedIP) error {
	args := m.Called(ctx, whitelistedIP)
	return args.Error(0)
}

func (m *MockWhitelistedIPRepository) Delete(ctx context.Context, id uint) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockWhitelistedIPRepository) IsWhitelisted(ctx context.Context, ip string) (bool, error) {
	args := m.Called(ctx, ip)
	return args.Bool(0), args.Error(1)
}

func (m *MockWhitelistedIPRepository) Count(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockWhitelistedIPRepository) Restore(ctx context.Context, ip string) (*models.WhitelistedIP, error) {
	args := m.Called(ctx, ip)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.WhitelistedIP), args.Error(1)
}

func (m *MockWhitelistedIPRepository) ExistsSoftDeleted(ctx context.Context, ip string) (*models.WhitelistedIP, error) {
	args := m.Called(ctx, ip)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.WhitelistedIP), args.Error(1)
}

func (m *MockWhitelistedIPRepository) FindPaginated(ctx context.Context, offset int, limit int) ([]models.WhitelistedIP, int64, error) {
	args := m.Called(ctx, offset, limit)
	return args.Get(0).([]models.WhitelistedIP), args.Get(1).(int64), args.Error(2)
}