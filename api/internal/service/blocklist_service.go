package service

import (
	"context"
	"fmt"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/logger"
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
	startTime := time.Now()
	logger.Log.WithFields(map[string]interface{}{
		"operation":   "block_ip",
		"ip_address":  blockedIP.IPAddress,
		"description": blockedIP.Description,
		"permanent":   blockedIP.Permanent,
	}).Info("Starting IP block operation")

	if blockedIP == nil {
		logger.Log.WithFields(map[string]interface{}{
			"operation": "block_ip",
		}).Error("Validation failed: blocked IP cannot be nil")
		return fmt.Errorf("blocked IP cannot be nil")
	}
	if blockedIP.IPAddress == "" {
		logger.Log.WithFields(map[string]interface{}{
			"operation": "block_ip",
		}).Error("Validation failed: IP address cannot be empty")
		return fmt.Errorf("IP address cannot be empty")
	}

	err := s.blockedIPRepo.Create(ctx, blockedIP)
	duration := time.Since(startTime).Milliseconds()

	if err != nil {
		logger.Log.WithFields(map[string]interface{}{
			"operation":   "block_ip",
			"ip_address":  blockedIP.IPAddress,
			"description": blockedIP.Description,
			"duration_ms": duration,
		}).WithError(err).Error("Failed to block IP")
		return err
	}

	logger.Log.WithFields(map[string]interface{}{
		"operation":   "block_ip",
		"ip_address":  blockedIP.IPAddress,
		"description": blockedIP.Description,
		"permanent":   blockedIP.Permanent,
		"duration_ms": duration,
	}).Info("IP blocked successfully")

	return nil
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
	startTime := time.Now()
	logger.Log.WithFields(map[string]interface{}{
		"operation":  "unblock_ip",
		"ip_address": ip,
	}).Info("Starting IP unblock operation")

	if ip == "" {
		logger.Log.WithFields(map[string]interface{}{
			"operation": "unblock_ip",
		}).Error("Validation failed: IP address cannot be empty")
		return fmt.Errorf("IP address cannot be empty")
	}

	err := s.blockedIPRepo.Delete(ctx, ip)
	duration := time.Since(startTime).Milliseconds()

	if err != nil {
		logger.Log.WithFields(map[string]interface{}{
			"operation":   "unblock_ip",
			"ip_address":  ip,
			"duration_ms": duration,
		}).WithError(err).Error("Failed to unblock IP")
		return err
	}

	logger.Log.WithFields(map[string]interface{}{
		"operation":   "unblock_ip",
		"ip_address":  ip,
		"duration_ms": duration,
	}).Info("IP unblocked successfully")

	return nil
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
