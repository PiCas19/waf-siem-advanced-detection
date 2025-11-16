package repository

import (
	"context"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"gorm.io/gorm"
)

type GormBlockedIPRepository struct {
	db *gorm.DB
}

func NewGormBlockedIPRepository(db *gorm.DB) BlockedIPRepository {
	return &GormBlockedIPRepository{db: db}
}

func (r *GormBlockedIPRepository) FindAll(ctx context.Context) ([]models.BlockedIP, error) {
	var blockedIPs []models.BlockedIP
	err := r.db.WithContext(ctx).Order("created_at DESC").Find(&blockedIPs).Error
	return blockedIPs, err
}

func (r *GormBlockedIPRepository) FindByIP(ctx context.Context, ip string) (*models.BlockedIP, error) {
	var blockedIP models.BlockedIP
	err := r.db.WithContext(ctx).Where("ip_address = ?", ip).First(&blockedIP).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return &blockedIP, err
}

func (r *GormBlockedIPRepository) FindActive(ctx context.Context) ([]models.BlockedIP, error) {
	var blockedIPs []models.BlockedIP
	now := time.Now()
	err := r.db.WithContext(ctx).
		Where("permanent = ? OR expires_at > ?", true, now).
		Order("created_at DESC").
		Find(&blockedIPs).Error
	return blockedIPs, err
}

func (r *GormBlockedIPRepository) Create(ctx context.Context, blockedIP *models.BlockedIP) error {
	return r.db.WithContext(ctx).Create(blockedIP).Error
}

func (r *GormBlockedIPRepository) Update(ctx context.Context, blockedIP *models.BlockedIP) error {
	return r.db.WithContext(ctx).Save(blockedIP).Error
}

func (r *GormBlockedIPRepository) Delete(ctx context.Context, ip string) error {
	return r.db.WithContext(ctx).Where("ip_address = ?", ip).Delete(&models.BlockedIP{}).Error
}

func (r *GormBlockedIPRepository) IsBlocked(ctx context.Context, ip string) (bool, error) {
	var count int64
	now := time.Now()
	err := r.db.WithContext(ctx).
		Model(&models.BlockedIP{}).
		Where("ip_address = ? AND (permanent = ? OR expires_at > ?)", ip, true, now).
		Count(&count).Error
	return count > 0, err
}

func (r *GormBlockedIPRepository) Count(ctx context.Context) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.BlockedIP{}).Count(&count).Error
	return count, err
}

func (r *GormBlockedIPRepository) FindByIPAndDescription(ctx context.Context, ip string, description string) (*models.BlockedIP, error) {
	var blockedIP models.BlockedIP
	err := r.db.WithContext(ctx).Where("ip_address = ? AND description = ?", ip, description).First(&blockedIP).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return &blockedIP, err
}
