package service

import (
	"context"
	"fmt"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/repository"
)

// BlocklistService handles business logic for blocked IPs
type BlocklistService struct {
	blockedIPRepo repository.BlockedIPRepository
	logRepo       repository.LogRepository
}

// NewBlocklistService creates a new blocklist service
func NewBlocklistService(blockedIPRepo repository.BlockedIPRepository, logRepo repository.LogRepository) *BlocklistService {
	return &BlocklistService{
		blockedIPRepo: blockedIPRepo,
		logRepo:       logRepo,
	}
}

// GetAllBlockedIPs retrieves all blocked IPs
func (s *BlocklistService) GetAllBlockedIPs(ctx context.Context) ([]models.BlockedIP, error) {
	return s.blockedIPRepo.FindAll(ctx)
}

// GetBlockedIPByIP retrieves a blocked IP by address
func (s *BlocklistService) GetBlockedIPByIP(ctx context.Context, ip string) (*models.BlockedIP, error) {
	if ip == "" {
		return nil, fmt.Errorf("IP address cannot be empty")
	}
	return s.blockedIPRepo.FindByIP(ctx, ip)
}

// GetActiveBlockedIPs retrieves all active blocked IPs (permanent or not expired)
func (s *BlocklistService) GetActiveBlockedIPs(ctx context.Context) ([]models.BlockedIP, error) {
	return s.blockedIPRepo.FindActive(ctx)
}

// IsIPBlocked checks if an IP is currently blocked
func (s *BlocklistService) IsIPBlocked(ctx context.Context, ip string) (bool, error) {
	if ip == "" {
		return false, fmt.Errorf("IP address cannot be empty")
	}
	return s.blockedIPRepo.IsBlocked(ctx, ip)
}

// GetBlockedIPsCount returns total number of blocked IPs
func (s *BlocklistService) GetBlockedIPsCount(ctx context.Context) (int64, error) {
	return s.blockedIPRepo.Count(ctx)
}

// BlockIP adds an IP to the blocklist
func (s *BlocklistService) BlockIP(ctx context.Context, blockedIP *models.BlockedIP) error {
	if blockedIP == nil {
		return fmt.Errorf("blocked IP cannot be nil")
	}
	if blockedIP.IPAddress == "" {
		return fmt.Errorf("IP address cannot be empty")
	}
	return s.blockedIPRepo.Create(ctx, blockedIP)
}

// UpdateBlockedIP updates a blocked IP entry
func (s *BlocklistService) UpdateBlockedIP(ctx context.Context, blockedIP *models.BlockedIP) error {
	if blockedIP == nil {
		return fmt.Errorf("blocked IP cannot be nil")
	}
	if blockedIP.IPAddress == "" {
		return fmt.Errorf("IP address cannot be empty")
	}
	return s.blockedIPRepo.Update(ctx, blockedIP)
}

// UnblockIP removes an IP from the blocklist
func (s *BlocklistService) UnblockIP(ctx context.Context, ip string) error {
	if ip == "" {
		return fmt.Errorf("IP address cannot be empty")
	}
	return s.blockedIPRepo.Delete(ctx, ip)
}

// BlockIPWithLogUpdate blocks an IP and updates related logs
func (s *BlocklistService) BlockIPWithLogUpdate(ctx context.Context, blockedIP *models.BlockedIP) error {
	if blockedIP == nil {
		return fmt.Errorf("blocked IP cannot be nil")
	}
	if blockedIP.IPAddress == "" {
		return fmt.Errorf("IP address cannot be empty")
	}

	// Create the blocked IP entry
	if err := s.blockedIPRepo.Create(ctx, blockedIP); err != nil {
		return fmt.Errorf("failed to create blocked IP: %w", err)
	}

	// Update related logs to mark them as blocked
	updates := map[string]interface{}{
		"blocked":   true,
		"blocked_by": "manual",
	}
	if err := s.logRepo.UpdateByIPAndDescription(ctx, blockedIP.IPAddress, blockedIP.Description, updates); err != nil {
		return fmt.Errorf("failed to update logs: %w", err)
	}

	return nil
}

// GetBlockedIPByIPAndDescription retrieves a blocked IP by IP and description
func (s *BlocklistService) GetBlockedIPByIPAndDescription(ctx context.Context, ip string, description string) (*models.BlockedIP, error) {
	if ip == "" || description == "" {
		return nil, fmt.Errorf("IP and description cannot be empty")
	}
	return s.blockedIPRepo.FindByIPAndDescription(ctx, ip, description)
}
