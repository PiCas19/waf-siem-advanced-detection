package repository

import (
	"context"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
)

// LogRepository handles all database operations for logs
type LogRepository interface {
	FindAll(ctx context.Context) ([]models.Log, error)
	FindByID(ctx context.Context, id uint) (*models.Log, error)
	FindByIP(ctx context.Context, ip string) ([]models.Log, error)
	FindBlocked(ctx context.Context) ([]models.Log, error)
	FindByThreatType(ctx context.Context, threatType string) ([]models.Log, error)
	FindRecent(ctx context.Context, limit int) ([]models.Log, error)
	Count(ctx context.Context) (int64, error)
	CountBlocked(ctx context.Context) (int64, error)
	Create(ctx context.Context, log *models.Log) error
	Update(ctx context.Context, log *models.Log) error
	Delete(ctx context.Context, id uint) error
	UpdateByIPAndDescription(ctx context.Context, ip string, description string, updates map[string]interface{}) error
	UpdateDetectedByIPAndDescription(ctx context.Context, ip string, description string, updates map[string]interface{}) error
	FindPaginated(ctx context.Context, offset int, limit int) ([]models.Log, int64, error)
	DeleteManualBlockLog(ctx context.Context, ip string, description string) error
}

// RuleRepository handles database operations for WAF rules
type RuleRepository interface {
	FindAll(ctx context.Context) ([]models.Rule, error)
	FindByID(ctx context.Context, id uint) (*models.Rule, error)
	FindEnabled(ctx context.Context) ([]models.Rule, error)
	Create(ctx context.Context, rule *models.Rule) error
	Update(ctx context.Context, rule *models.Rule) error
	Delete(ctx context.Context, id uint) error
	ToggleEnabled(ctx context.Context, id uint, enabled bool) error
	Count(ctx context.Context) (int64, error)
	FindByType(ctx context.Context, threatType string) ([]models.Rule, error)
}

// BlockedIPRepository handles database operations for blocked IPs
type BlockedIPRepository interface {
	FindAll(ctx context.Context) ([]models.BlockedIP, error)
	FindByIP(ctx context.Context, ip string) (*models.BlockedIP, error)
	FindActive(ctx context.Context) ([]models.BlockedIP, error)
	Create(ctx context.Context, blockedIP *models.BlockedIP) error
	Update(ctx context.Context, blockedIP *models.BlockedIP) error
	Delete(ctx context.Context, ip string) error
	IsBlocked(ctx context.Context, ip string) (bool, error)
	Count(ctx context.Context) (int64, error)
	FindByIPAndDescription(ctx context.Context, ip string, description string) (*models.BlockedIP, error)
}

// WhitelistedIPRepository handles database operations for whitelisted IPs
type WhitelistedIPRepository interface {
	FindAll(ctx context.Context) ([]models.WhitelistedIP, error)
	FindByIP(ctx context.Context, ip string) (*models.WhitelistedIP, error)
	Create(ctx context.Context, whitelistedIP *models.WhitelistedIP) error
	Update(ctx context.Context, whitelistedIP *models.WhitelistedIP) error
	Delete(ctx context.Context, id uint) error
	IsWhitelisted(ctx context.Context, ip string) (bool, error)
	Count(ctx context.Context) (int64, error)
	Restore(ctx context.Context, ip string) (*models.WhitelistedIP, error)
	ExistsSoftDeleted(ctx context.Context, ip string) (*models.WhitelistedIP, error)
}

// AuditLogRepository handles database operations for audit logs
type AuditLogRepository interface {
	FindAll(ctx context.Context) ([]models.AuditLog, error)
	FindByUser(ctx context.Context, userID uint) ([]models.AuditLog, error)
	FindByAction(ctx context.Context, action string) ([]models.AuditLog, error)
	FindRecent(ctx context.Context, limit int) ([]models.AuditLog, error)
	Create(ctx context.Context, auditLog *models.AuditLog) error
	Count(ctx context.Context) (int64, error)
	CountByStatus(ctx context.Context, status string) (int64, error)
	FindPaginated(ctx context.Context, offset int, limit int) ([]models.AuditLog, int64, error)
	GetActionBreakdown(ctx context.Context) (map[string]int64, error)
}

// FalsePositiveRepository handles database operations for false positives
type FalsePositiveRepository interface {
	FindAll(ctx context.Context) ([]models.FalsePositive, error)
	FindByID(ctx context.Context, id uint) (*models.FalsePositive, error)
	FindByIP(ctx context.Context, ip string) ([]models.FalsePositive, error)
	FindUnresolved(ctx context.Context) ([]models.FalsePositive, error)
	Create(ctx context.Context, fp *models.FalsePositive) error
	Update(ctx context.Context, fp *models.FalsePositive) error
	Delete(ctx context.Context, id uint) error
	Count(ctx context.Context) (int64, error)
	CountUnresolved(ctx context.Context) (int64, error)
	FindPaginated(ctx context.Context, offset int, limit int) ([]models.FalsePositive, int64, error)
}

// UserRepository handles database operations for users
type UserRepository interface {
	FindAll(ctx context.Context) ([]models.User, error)
	FindByID(ctx context.Context, id uint) (*models.User, error)
	FindByEmail(ctx context.Context, email string) (*models.User, error)
	Create(ctx context.Context, user *models.User) error
	Update(ctx context.Context, user *models.User) error
	Delete(ctx context.Context, id uint) error
	Count(ctx context.Context) (int64, error)
	UpdateRole(ctx context.Context, id uint, role string) error
	FindByRole(ctx context.Context, role string) ([]models.User, error)
	CountByRole(ctx context.Context, role string) (int64, error)
	ExistsByEmail(ctx context.Context, email string) (bool, error)
}
