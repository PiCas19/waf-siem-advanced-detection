package repository

import (
	"context"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/logger"
	"gorm.io/gorm"
)

type GormRuleRepository struct {
	db *gorm.DB
}

func NewGormRuleRepository(db *gorm.DB) RuleRepository {
	return &GormRuleRepository{db: db}
}

func (r *GormRuleRepository) FindAll(ctx context.Context) ([]models.Rule, error) {
	startTime := time.Now()
	var rules []models.Rule
	err := r.db.WithContext(ctx).Order("created_at DESC").Find(&rules).Error
	duration := time.Since(startTime).Milliseconds()

	if err != nil {
		logger.Log.WithFields(map[string]interface{}{
			"operation":   "rule_repo_find_all",
			"duration_ms": duration,
		}).WithError(err).Error("Database query failed")
	} else {
		logger.Log.WithFields(map[string]interface{}{
			"operation":   "rule_repo_find_all",
			"count":       len(rules),
			"duration_ms": duration,
		}).Debug("Database query successful")
	}

	return rules, err
}

func (r *GormRuleRepository) FindByID(ctx context.Context, id uint) (*models.Rule, error) {
	var rule models.Rule
	err := r.db.WithContext(ctx).First(&rule, id).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return &rule, err
}

func (r *GormRuleRepository) FindEnabled(ctx context.Context) ([]models.Rule, error) {
	var rules []models.Rule
	err := r.db.WithContext(ctx).Where("enabled = ?", true).Order("created_at DESC").Find(&rules).Error
	return rules, err
}

func (r *GormRuleRepository) Create(ctx context.Context, rule *models.Rule) error {
	startTime := time.Now()
	err := r.db.WithContext(ctx).Create(rule).Error
	duration := time.Since(startTime).Milliseconds()

	if err != nil {
		logger.Log.WithFields(map[string]interface{}{
			"operation":   "rule_repo_create",
			"rule_name":   rule.Name,
			"duration_ms": duration,
		}).WithError(err).Error("Database insert failed")
	} else {
		logger.Log.WithFields(map[string]interface{}{
			"operation":   "rule_repo_create",
			"rule_id":     rule.ID,
			"rule_name":   rule.Name,
			"duration_ms": duration,
		}).Debug("Database insert successful")
	}

	return err
}

func (r *GormRuleRepository) Update(ctx context.Context, rule *models.Rule) error {
	return r.db.WithContext(ctx).Save(rule).Error
}

func (r *GormRuleRepository) Delete(ctx context.Context, id uint) error {
	startTime := time.Now()
	err := r.db.WithContext(ctx).Delete(&models.Rule{}, id).Error
	duration := time.Since(startTime).Milliseconds()

	if err != nil {
		logger.Log.WithFields(map[string]interface{}{
			"operation":   "rule_repo_delete",
			"rule_id":     id,
			"duration_ms": duration,
		}).WithError(err).Error("Database delete failed")
	} else {
		logger.Log.WithFields(map[string]interface{}{
			"operation":   "rule_repo_delete",
			"rule_id":     id,
			"duration_ms": duration,
		}).Debug("Database delete successful")
	}

	return err
}

func (r *GormRuleRepository) ToggleEnabled(ctx context.Context, id uint, enabled bool) error {
	return r.db.WithContext(ctx).Model(&models.Rule{}).Where("id = ?", id).Update("enabled", enabled).Error
}

func (r *GormRuleRepository) Count(ctx context.Context) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.Rule{}).Count(&count).Error
	return count, err
}

func (r *GormRuleRepository) FindByType(ctx context.Context, threatType string) ([]models.Rule, error) {
	var rules []models.Rule
	err := r.db.WithContext(ctx).Where("type = ? AND enabled = ?", threatType, true).Order("created_at DESC").Find(&rules).Error
	return rules, err
}

func (r *GormRuleRepository) FindPaginated(ctx context.Context, offset int, limit int) ([]models.Rule, int64, error) {
	var rules []models.Rule
	var total int64

	// Get total count
	if err := r.db.WithContext(ctx).Model(&models.Rule{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Get paginated results
	err := r.db.WithContext(ctx).
		Order("created_at DESC").
		Offset(offset).
		Limit(limit).
		Find(&rules).Error

	return rules, total, err
}
