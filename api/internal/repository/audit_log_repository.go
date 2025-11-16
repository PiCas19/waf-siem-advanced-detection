package repository

import (
	"context"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"gorm.io/gorm"
)

type GormAuditLogRepository struct {
	db *gorm.DB
}

func NewGormAuditLogRepository(db *gorm.DB) AuditLogRepository {
	return &GormAuditLogRepository{db: db}
}

func (r *GormAuditLogRepository) FindAll(ctx context.Context) ([]models.AuditLog, error) {
	var auditLogs []models.AuditLog
	err := r.db.WithContext(ctx).Order("created_at DESC").Find(&auditLogs).Error
	return auditLogs, err
}

func (r *GormAuditLogRepository) FindByUser(ctx context.Context, userID uint) ([]models.AuditLog, error) {
	var auditLogs []models.AuditLog
	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Find(&auditLogs).Error
	return auditLogs, err
}

func (r *GormAuditLogRepository) FindByAction(ctx context.Context, action string) ([]models.AuditLog, error) {
	var auditLogs []models.AuditLog
	err := r.db.WithContext(ctx).
		Where("action = ?", action).
		Order("created_at DESC").
		Find(&auditLogs).Error
	return auditLogs, err
}

func (r *GormAuditLogRepository) FindRecent(ctx context.Context, limit int) ([]models.AuditLog, error) {
	var auditLogs []models.AuditLog
	err := r.db.WithContext(ctx).
		Order("created_at DESC").
		Limit(limit).
		Find(&auditLogs).Error
	return auditLogs, err
}

func (r *GormAuditLogRepository) Create(ctx context.Context, auditLog *models.AuditLog) error {
	return r.db.WithContext(ctx).Create(auditLog).Error
}

func (r *GormAuditLogRepository) Count(ctx context.Context) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.AuditLog{}).Count(&count).Error
	return count, err
}

func (r *GormAuditLogRepository) CountByStatus(ctx context.Context, status string) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).
		Model(&models.AuditLog{}).
		Where("status = ?", status).
		Count(&count).Error
	return count, err
}

// FindPaginated retrieves paginated audit logs with optional filtering
func (r *GormAuditLogRepository) FindPaginated(ctx context.Context, offset int, limit int) ([]models.AuditLog, int64, error) {
	var auditLogs []models.AuditLog
	var total int64

	query := r.db.WithContext(ctx)

	// Get total count
	if err := query.Model(&models.AuditLog{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Get paginated results
	err := query.
		Order("created_at DESC").
		Offset(offset).
		Limit(limit).
		Find(&auditLogs).Error

	return auditLogs, total, err
}

// GetActionBreakdown returns count of audit logs grouped by action
func (r *GormAuditLogRepository) GetActionBreakdown(ctx context.Context) (map[string]int64, error) {
	type ActionCount struct {
		Action string
		Count  int64
	}

	var results []ActionCount
	err := r.db.WithContext(ctx).
		Model(&models.AuditLog{}).
		Select("action, count(*) as count").
		Group("action").
		Scan(&results).Error

	if err != nil {
		return nil, err
	}

	breakdown := make(map[string]int64)
	for _, result := range results {
		breakdown[result.Action] = result.Count
	}

	return breakdown, nil
}
