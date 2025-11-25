package repository

import (
	"context"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/logger"
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
	logger.Log.WithField("count", len(whitelisted)).Info("Fetched whitelisted IPs")
	if err != nil {
		logger.Log.WithError(err).Error("Failed to fetch whitelisted IPs")
	}
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
	logger.Log.WithField("ip", whitelistedIP.IPAddress).Info("Creating whitelist entry")
	result := r.db.WithContext(ctx).Create(whitelistedIP)
	if result.Error != nil {
		logger.Log.WithError(result.Error).WithField("ip", whitelistedIP.IPAddress).Error("Failed to create whitelist entry")
		return result.Error
	}
	logger.Log.WithField("ip", whitelistedIP.IPAddress).WithField("id", whitelistedIP.ID).Info("Whitelist entry created successfully")
	return nil
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

func (r *GormWhitelistedIPRepository) FindPaginated(ctx context.Context, offset int, limit int) ([]models.WhitelistedIP, int64, error) {
	var whitelisted []models.WhitelistedIP
	var total int64

	// Get total count
	if err := r.db.WithContext(ctx).Model(&models.WhitelistedIP{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Get paginated results
	err := r.db.WithContext(ctx).
		Order("created_at DESC").
		Offset(offset).
		Limit(limit).
		Find(&whitelisted).Error

	return whitelisted, total, err
}
