package repository

import (
	"context"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"gorm.io/gorm"
)

type GormFalsePositiveRepository struct {
	db *gorm.DB
}

func NewGormFalsePositiveRepository(db *gorm.DB) FalsePositiveRepository {
	return &GormFalsePositiveRepository{db: db}
}

func (r *GormFalsePositiveRepository) FindAll(ctx context.Context) ([]models.FalsePositive, error) {
	var falsePositives []models.FalsePositive
	err := r.db.WithContext(ctx).Order("created_at DESC").Find(&falsePositives).Error
	return falsePositives, err
}

func (r *GormFalsePositiveRepository) FindByID(ctx context.Context, id uint) (*models.FalsePositive, error) {
	var falsePositive models.FalsePositive
	err := r.db.WithContext(ctx).First(&falsePositive, id).Error
	if err == gorm.ErrRecordNotFound {
		return nil, nil
	}
	return &falsePositive, err
}

func (r *GormFalsePositiveRepository) FindByIP(ctx context.Context, ip string) ([]models.FalsePositive, error) {
	var falsePositives []models.FalsePositive
	err := r.db.WithContext(ctx).
		Where("ip_address = ?", ip).
		Order("created_at DESC").
		Find(&falsePositives).Error
	return falsePositives, err
}

func (r *GormFalsePositiveRepository) FindUnresolved(ctx context.Context) ([]models.FalsePositive, error) {
	var falsePositives []models.FalsePositive
	err := r.db.WithContext(ctx).
		Where("resolved = ?", false).
		Order("created_at DESC").
		Find(&falsePositives).Error
	return falsePositives, err
}

func (r *GormFalsePositiveRepository) Create(ctx context.Context, fp *models.FalsePositive) error {
	return r.db.WithContext(ctx).Create(fp).Error
}

func (r *GormFalsePositiveRepository) Update(ctx context.Context, fp *models.FalsePositive) error {
	return r.db.WithContext(ctx).Save(fp).Error
}

func (r *GormFalsePositiveRepository) Delete(ctx context.Context, id uint) error {
	return r.db.WithContext(ctx).Delete(&models.FalsePositive{}, id).Error
}

func (r *GormFalsePositiveRepository) Count(ctx context.Context) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&models.FalsePositive{}).Count(&count).Error
	return count, err
}

// CountUnresolved returns count of unresolved false positives
func (r *GormFalsePositiveRepository) CountUnresolved(ctx context.Context) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).
		Model(&models.FalsePositive{}).
		Where("resolved = ?", false).
		Count(&count).Error
	return count, err
}

// FindPaginated returns paginated false positives with optional filtering
func (r *GormFalsePositiveRepository) FindPaginated(ctx context.Context, offset int, limit int) ([]models.FalsePositive, int64, error) {
	var falsePositives []models.FalsePositive
	var total int64

	query := r.db.WithContext(ctx)

	// Get total count
	if err := query.Model(&models.FalsePositive{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Get paginated results
	err := query.
		Order("created_at DESC").
		Offset(offset).
		Limit(limit).
		Find(&falsePositives).Error

	return falsePositives, total, err
}
