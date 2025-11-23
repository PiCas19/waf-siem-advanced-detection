package repository

import (
	"context"
	"fmt"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"gorm.io/gorm"
)

type GormLogRepository struct {
	db *gorm.DB
}

func NewGormLogRepository(db *gorm.DB) LogRepository {
	return &GormLogRepository{db: db}
}

func (r *GormLogRepository) FindAll(ctx context.Context) ([]models.Log, error) {
	var logs []models.Log
	err := r.db.WithContext(ctx).Order("created_at DESC").Find(&logs).Error
	return logs, err
}

func (r *GormLogRepository) FindByID(ctx context.Context, id uint) (*models.Log, error) {
	var log models.Log
	err := r.db.WithContext(ctx).First(&log, id).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return &log, err
}

func (r *GormLogRepository) FindByIP(ctx context.Context, ip string) ([]models.Log, error) {
	var logs []models.Log
	err := r.db.WithContext(ctx).Where("client_ip = ?", ip).Order("created_at DESC").Find(&logs).Error
	return logs, err
}

func (r *GormLogRepository) FindBlocked(ctx context.Context) ([]models.Log, error) {
	var logs []models.Log
	err := r.db.WithContext(ctx).Where("blocked = ?", true).Order("created_at DESC").Find(&logs).Error
	return logs, err
}

func (r *GormLogRepository) FindByThreatType(ctx context.Context, threatType string) ([]models.Log, error) {
	var logs []models.Log
	err := r.db.WithContext(ctx).Where("threat_type = ?", threatType).Order("created_at DESC").Find(&logs).Error
	return logs, err
}

func (r *GormLogRepository) FindRecent(ctx context.Context, limit int) ([]models.Log, error) {
	var logs []models.Log
	err := r.db.WithContext(ctx).Order("created_at DESC").Limit(limit).Find(&logs).Error
	return logs, err
}

func (r *GormLogRepository) Count(ctx context.Context) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.Log{}).Count(&count).Error
	return count, err
}

func (r *GormLogRepository) CountBlocked(ctx context.Context) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.Log{}).Where("blocked = ?", true).Count(&count).Error
	return count, err
}

func (r *GormLogRepository) Create(ctx context.Context, log *models.Log) error {
	return r.db.WithContext(ctx).Create(log).Error
}

func (r *GormLogRepository) Update(ctx context.Context, log *models.Log) error {
	return r.db.WithContext(ctx).Save(log).Error
}

func (r *GormLogRepository) Delete(ctx context.Context, id uint) error {
	return r.db.WithContext(ctx).Delete(&models.Log{}, id).Error
}

func (r *GormLogRepository) UpdateByIPAndDescription(ctx context.Context, ip string, description string, updates map[string]interface{}) error {
	query := r.db.WithContext(ctx).
		Model(&models.Log{}).
		Where("client_ip = ? AND (threat_type = ? OR description = ?)", ip, description, description)

	result := query.Updates(updates)

	// Log for debugging
	fmt.Printf("[INFO] UpdateByIPAndDescription: IP=%s, description=%s, RowsAffected=%d\n", ip, description, result.RowsAffected)
	if result.RowsAffected == 0 {
		fmt.Printf("[WARN] UpdateByIPAndDescription: No rows updated. Checking what logs exist for this IP...\n")
		// Check what logs exist for this IP
		var existingLogs []models.Log
		r.db.WithContext(ctx).Where("client_ip = ?", ip).Find(&existingLogs)
		fmt.Printf("[WARN] Found %d logs for IP %s:\n", len(existingLogs), ip)
		for _, log := range existingLogs {
			fmt.Printf("  - threat_type=%s, description=%s, blocked=%v\n", log.ThreatType, log.Description, log.Blocked)
		}
	}

	return result.Error
}

// UpdateDetectedByIPAndDescription updates only DETECTED (not blocked) logs matching IP and description
// This ensures that when manually blocking, we only update the detected threat, not the already-blocked ones
func (r *GormLogRepository) UpdateDetectedByIPAndDescription(ctx context.Context, ip string, description string, updates map[string]interface{}) error {
	query := r.db.WithContext(ctx).
		Model(&models.Log{}).
		Where("client_ip = ? AND (threat_type = ? OR description = ?) AND blocked = ?", ip, description, description, false)

	result := query.Updates(updates)

	// Log for debugging
	if result.RowsAffected == 0 {
		fmt.Printf("[WARN] UpdateDetectedByIPAndDescription: No rows updated for IP=%s, description=%s. Checking what exists...\n", ip, description)
		// Check what logs exist for this IP
		var existingLogs []models.Log
		r.db.WithContext(ctx).Where("client_ip = ?", ip).Find(&existingLogs)
		for _, log := range existingLogs {
			fmt.Printf("  Existing log: threat_type=%s, description=%s, blocked=%v\n", log.ThreatType, log.Description, log.Blocked)
		}
	}

	return result.Error
}

func (r *GormLogRepository) FindPaginated(ctx context.Context, offset int, limit int) ([]models.Log, int64, error) {
	var logs []models.Log
	var total int64

	query := r.db.WithContext(ctx)

	// Get total count
	if err := query.Model(&models.Log{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Get paginated results
	err := query.
		Order("created_at DESC").
		Offset(offset).
		Limit(limit).
		Find(&logs).Error

	return logs, total, err
}

// DeleteManualBlockLog deletes the manual block log entry (blocked_by="manual" and method="MANUAL_BLOCK")
// This removes the "Blocked manually" status when unblocking a threat
func (r *GormLogRepository) DeleteManualBlockLog(ctx context.Context, ip string, description string) error {
	return r.db.WithContext(ctx).
		Where("client_ip = ? AND (threat_type = ? OR description = ?) AND blocked_by = ? AND method = ?",
			ip, description, description, "manual", "MANUAL_BLOCK").
		Delete(&models.Log{}).Error
}
