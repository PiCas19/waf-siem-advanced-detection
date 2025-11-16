package repository

import (
	"context"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"gorm.io/gorm"
)

type GormRuleRepository struct {
	db *gorm.DB
}

func NewGormRuleRepository(db *gorm.DB) RuleRepository {
	return &GormRuleRepository{db: db}
}

func (r *GormRuleRepository) FindAll(ctx context.Context) ([]models.Rule, error) {
	var rules []models.Rule
	err := r.db.WithContext(ctx).Order("created_at DESC").Find(&rules).Error
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
	return r.db.WithContext(ctx).Create(rule).Error
}

func (r *GormRuleRepository) Update(ctx context.Context, rule *models.Rule) error {
	return r.db.WithContext(ctx).Save(rule).Error
}

func (r *GormRuleRepository) Delete(ctx context.Context, id uint) error {
	return r.db.WithContext(ctx).Delete(&models.Rule{}, id).Error
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
