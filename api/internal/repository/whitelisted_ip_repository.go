package repository

import (
	"context"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"gorm.io/gorm"
)

type GormWhitelistedIPRepository struct {
	db *gorm.DB
}

func NewGormWhitelistedIPRepository(db *gorm.DB) WhitelistedIPRepository {
	return &GormWhitelistedIPRepository{db: db}
}

func (r *GormWhitelistedIPRepository) FindAll(ctx context.Context) ([]models.WhitelistedIP, error) {
	var whitelisted []models.WhitelistedIP
	err := r.db.WithContext(ctx).Order("created_at DESC").Find(&whitelisted).Error
	return whitelisted, err
}

func (r *GormWhitelistedIPRepository) FindByIP(ctx context.Context, ip string) (*models.WhitelistedIP, error) {
	var whitelisted models.WhitelistedIP
	err := r.db.WithContext(ctx).Where("ip_address = ?", ip).First(&whitelisted).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return &whitelisted, err
}

func (r *GormWhitelistedIPRepository) Create(ctx context.Context, whitelistedIP *models.WhitelistedIP) error {
	return r.db.WithContext(ctx).Create(whitelistedIP).Error
}

func (r *GormWhitelistedIPRepository) Update(ctx context.Context, whitelistedIP *models.WhitelistedIP) error {
	return r.db.WithContext(ctx).Save(whitelistedIP).Error
}

func (r *GormWhitelistedIPRepository) Delete(ctx context.Context, id uint) error {
	return r.db.WithContext(ctx).Delete(&models.WhitelistedIP{}, id).Error
}

func (r *GormWhitelistedIPRepository) IsWhitelisted(ctx context.Context, ip string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).
		Model(&models.WhitelistedIP{}).
		Where("ip_address = ?", ip).
		Count(&count).Error
	return count > 0, err
}

func (r *GormWhitelistedIPRepository) Count(ctx context.Context) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.WhitelistedIP{}).Count(&count).Error
	return count, err
}

// Restore restores a soft-deleted whitelisted IP
func (r *GormWhitelistedIPRepository) Restore(ctx context.Context, ip string) (*models.WhitelistedIP, error) {
	var whitelisted models.WhitelistedIP
	err := r.db.WithContext(ctx).
		Unscoped().
		Where("ip_address = ?", ip).
		First(&whitelisted).Error
	if err != nil {
		return nil, err
	}

	err = r.db.WithContext(ctx).
		Unscoped().
		Model(&whitelisted).
		Update("deleted_at", nil).Error
	if err != nil {
		return nil, err
	}

	return &whitelisted, nil
}

// ExistsSoftDeleted checks if a whitelisted IP exists including soft-deleted ones
func (r *GormWhitelistedIPRepository) ExistsSoftDeleted(ctx context.Context, ip string) (*models.WhitelistedIP, error) {
	var whitelisted models.WhitelistedIP
	err := r.db.WithContext(ctx).
		Unscoped().
		Where("ip_address = ?", ip).
		First(&whitelisted).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return &whitelisted, err
}
