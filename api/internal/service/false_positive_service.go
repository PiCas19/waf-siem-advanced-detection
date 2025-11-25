package service

import (
	"context"
	"fmt"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/repository"
)

// FalsePositiveService handles business logic for false positives, providing methods to
// report, review, and manage security events incorrectly flagged as threats.
//
// Fields:
//   - fpRepo (repository.FalsePositiveRepository): Repository for false positive operations
//
// Example Usage:
//   fpService := service.NewFalsePositiveService(fpRepo)
//   err := fpService.ReportFalsePositive(ctx, &models.FalsePositive{ThreatType: "xss"})
//
// Thread Safety: Thread-safe when using appropriate database transaction handling.
//
// See Also: FalsePositive, FalsePositiveRepository
type FalsePositiveService struct {
	fpRepo repository.FalsePositiveRepository
}

// NewFalsePositiveService creates a new false positive service
func NewFalsePositiveService(fpRepo repository.FalsePositiveRepository) *FalsePositiveService {
	return &FalsePositiveService{
		fpRepo: fpRepo,
	}
}

// GetAllFalsePositives retrieves all false positives
func (s *FalsePositiveService) GetAllFalsePositives(ctx context.Context) ([]models.FalsePositive, error) {
	return s.fpRepo.FindAll(ctx)
}

// GetFalsePositivesPaginated retrieves paginated false positives with total count
func (s *FalsePositiveService) GetFalsePositivesPaginated(ctx context.Context, offset, limit int) ([]models.FalsePositive, int64, error) {
	return s.fpRepo.FindPaginated(ctx, offset, limit)
}

// GetFalsePositiveByID retrieves a false positive by ID
func (s *FalsePositiveService) GetFalsePositiveByID(ctx context.Context, id uint) (*models.FalsePositive, error) {
	if id == 0 {
		return nil, fmt.Errorf("false positive ID must be set")
	}
	fp, err := s.fpRepo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get false positive: %w", err)
	}
	if fp == nil {
		return nil, fmt.Errorf("false positive not found")
	}
	return fp, nil
}

// GetFalsePositivesByIP retrieves false positives for a specific client IP
func (s *FalsePositiveService) GetFalsePositivesByIP(ctx context.Context, ip string) ([]models.FalsePositive, error) {
	if ip == "" {
		return nil, fmt.Errorf("client IP cannot be empty")
	}
	return s.fpRepo.FindByIP(ctx, ip)
}

// GetUnresolvedFalsePositives retrieves unresolved false positives
func (s *FalsePositiveService) GetUnresolvedFalsePositives(ctx context.Context) ([]models.FalsePositive, error) {
	return s.fpRepo.FindUnresolved(ctx)
}

// GetFalsePositivesCount returns total number of false positives
func (s *FalsePositiveService) GetFalsePositivesCount(ctx context.Context) (int64, error) {
	return s.fpRepo.Count(ctx)
}

// GetUnresolvedCount returns count of unresolved false positives
func (s *FalsePositiveService) GetUnresolvedCount(ctx context.Context) (int64, error) {
	return s.fpRepo.CountUnresolved(ctx)
}

// ReportFalsePositive reports a false positive
func (s *FalsePositiveService) ReportFalsePositive(ctx context.Context, fp *models.FalsePositive) error {
	if fp == nil {
		return fmt.Errorf("false positive cannot be nil")
	}
	if fp.ClientIP == "" {
		return fmt.Errorf("client IP cannot be empty")
	}
	if fp.ThreatType == "" {
		return fmt.Errorf("threat type cannot be empty")
	}
	return s.fpRepo.Create(ctx, fp)
}

// UpdateFalsePositive updates a false positive
func (s *FalsePositiveService) UpdateFalsePositive(ctx context.Context, fp *models.FalsePositive) error {
	if fp == nil {
		return fmt.Errorf("false positive cannot be nil")
	}
	if fp.ID == 0 {
		return fmt.Errorf("false positive ID must be set")
	}
	return s.fpRepo.Update(ctx, fp)
}

// ReviewFalsePositive marks a false positive as reviewed
func (s *FalsePositiveService) ReviewFalsePositive(ctx context.Context, id uint, status string, reviewNotes string, reviewedBy uint) error {
	if id == 0 {
		return fmt.Errorf("false positive ID must be set")
	}
	if status == "" {
		return fmt.Errorf("status cannot be empty")
	}

	fp, err := s.GetFalsePositiveByID(ctx, id)
	if err != nil {
		return err
	}

	fp.Status = status
	fp.ReviewNotes = reviewNotes
	fp.ReviewedBy = reviewedBy
	now := fp.CreatedAt // Will be overridden by UpdatedAt in GORM
	fp.ReviewedAt = &now
	return s.UpdateFalsePositive(ctx, fp)
}

// DeleteFalsePositive deletes a false positive
func (s *FalsePositiveService) DeleteFalsePositive(ctx context.Context, id uint) error {
	if id == 0 {
		return fmt.Errorf("false positive ID must be set")
	}
	return s.fpRepo.Delete(ctx, id)
}

// GetPaginatedFalsePositives returns paginated false positives
func (s *FalsePositiveService) GetPaginatedFalsePositives(ctx context.Context, page int, pageSize int) ([]models.FalsePositive, int64, error) {
	if page < 1 || pageSize < 1 {
		return nil, 0, fmt.Errorf("page and pageSize must be positive")
	}
	offset := (page - 1) * pageSize
	return s.fpRepo.FindPaginated(ctx, offset, pageSize)
}
