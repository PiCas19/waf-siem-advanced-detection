package service

import (
	"context"
	"fmt"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/repository"
)

// WhitelistService handles business logic for whitelisted IPs, providing methods to add,
// remove, and query whitelisted IP addresses that bypass security checks.
//
// Fields:
//   - whitelistRepo (repository.WhitelistedIPRepository): Repository for whitelist operations
//
// Example Usage:
//   whitelistService := service.NewWhitelistService(whitelistRepo)
//   err := whitelistService.AddToWhitelist(ctx, &models.WhitelistedIP{IPAddress: "203.0.113.42"})
//
// Thread Safety: Thread-safe when using appropriate database transaction handling.
//
// See Also: WhitelistedIP, WhitelistedIPRepository
type WhitelistService struct {
	whitelistRepo repository.WhitelistedIPRepository
}

// NewWhitelistService creates a new whitelist service
func NewWhitelistService(whitelistRepo repository.WhitelistedIPRepository) *WhitelistService {
	return &WhitelistService{
		whitelistRepo: whitelistRepo,
	}
}

// GetAllWhitelistedIPs retrieves all whitelisted IPs
func (s *WhitelistService) GetAllWhitelistedIPs(ctx context.Context) ([]models.WhitelistedIP, error) {
	return s.whitelistRepo.FindAll(ctx)
}

// GetWhitelistedIPByIP retrieves a whitelisted IP by address
func (s *WhitelistService) GetWhitelistedIPByIP(ctx context.Context, ip string) (*models.WhitelistedIP, error) {
	if ip == "" {
		return nil, fmt.Errorf("IP address cannot be empty")
	}
	return s.whitelistRepo.FindByIP(ctx, ip)
}

// IsIPWhitelisted checks if an IP is whitelisted
func (s *WhitelistService) IsIPWhitelisted(ctx context.Context, ip string) (bool, error) {
	if ip == "" {
		return false, fmt.Errorf("IP address cannot be empty")
	}
	return s.whitelistRepo.IsWhitelisted(ctx, ip)
}

// GetWhitelistedIPsCount returns total number of whitelisted IPs
func (s *WhitelistService) GetWhitelistedIPsCount(ctx context.Context) (int64, error) {
	return s.whitelistRepo.Count(ctx)
}

// GetWhitelistedIPsPaginated retrieves paginated whitelisted IPs with total count
func (s *WhitelistService) GetWhitelistedIPsPaginated(ctx context.Context, offset, limit int) ([]models.WhitelistedIP, int64, error) {
	return s.whitelistRepo.FindPaginated(ctx, offset, limit)
}

// AddToWhitelist adds an IP to the whitelist
func (s *WhitelistService) AddToWhitelist(ctx context.Context, whitelistedIP *models.WhitelistedIP) error {
	if whitelistedIP == nil {
		return fmt.Errorf("whitelisted IP cannot be nil")
	}
	if whitelistedIP.IPAddress == "" {
		return fmt.Errorf("IP address cannot be empty")
	}
	return s.whitelistRepo.Create(ctx, whitelistedIP)
}

// UpdateWhitelistedIP updates a whitelisted IP entry
func (s *WhitelistService) UpdateWhitelistedIP(ctx context.Context, whitelistedIP *models.WhitelistedIP) error {
	if whitelistedIP == nil {
		return fmt.Errorf("whitelisted IP cannot be nil")
	}
	if whitelistedIP.IPAddress == "" {
		return fmt.Errorf("IP address cannot be empty")
	}
	return s.whitelistRepo.Update(ctx, whitelistedIP)
}

// RemoveFromWhitelist removes an IP from the whitelist
func (s *WhitelistService) RemoveFromWhitelist(ctx context.Context, id uint) error {
	if id == 0 {
		return fmt.Errorf("whitelisted IP ID must be set")
	}
	return s.whitelistRepo.Delete(ctx, id)
}

// RestoreFromWhitelist restores a soft-deleted whitelisted IP
func (s *WhitelistService) RestoreFromWhitelist(ctx context.Context, ip string) (*models.WhitelistedIP, error) {
	if ip == "" {
		return nil, fmt.Errorf("IP address cannot be empty")
	}
	return s.whitelistRepo.Restore(ctx, ip)
}

// CheckWhitelistedIPExists checks if a whitelisted IP exists (including soft-deleted ones)
func (s *WhitelistService) CheckWhitelistedIPExists(ctx context.Context, ip string) (*models.WhitelistedIP, error) {
	if ip == "" {
		return nil, fmt.Errorf("IP address cannot be empty")
	}
	return s.whitelistRepo.ExistsSoftDeleted(ctx, ip)
}
