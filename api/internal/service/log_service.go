package service

import (
	"context"
	"fmt"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/repository"
)

// LogService handles business logic for logs
type LogService struct {
	logRepo repository.LogRepository
}

// NewLogService creates a new log service
func NewLogService(logRepo repository.LogRepository) *LogService {
	return &LogService{
		logRepo: logRepo,
	}
}

// GetAllLogs retrieves all logs
func (s *LogService) GetAllLogs(ctx context.Context) ([]models.Log, error) {
	return s.logRepo.FindAll(ctx)
}

// GetLogByID retrieves a log by ID
func (s *LogService) GetLogByID(ctx context.Context, id uint) (*models.Log, error) {
	log, err := s.logRepo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get log: %w", err)
	}
	if log == nil {
		return nil, fmt.Errorf("log not found")
	}
	return log, nil
}

// GetLogsByIP retrieves logs by IP address
func (s *LogService) GetLogsByIP(ctx context.Context, ip string) ([]models.Log, error) {
	if ip == "" {
		return nil, fmt.Errorf("IP address cannot be empty")
	}
	return s.logRepo.FindByIP(ctx, ip)
}

// GetBlockedLogs retrieves all blocked logs
func (s *LogService) GetBlockedLogs(ctx context.Context) ([]models.Log, error) {
	return s.logRepo.FindBlocked(ctx)
}

// GetLogsByThreatType retrieves logs by threat type
func (s *LogService) GetLogsByThreatType(ctx context.Context, threatType string) ([]models.Log, error) {
	if threatType == "" {
		return nil, fmt.Errorf("threat type cannot be empty")
	}
	return s.logRepo.FindByThreatType(ctx, threatType)
}

// GetRecentLogs retrieves recent logs
func (s *LogService) GetRecentLogs(ctx context.Context, limit int) ([]models.Log, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("limit must be positive")
	}
	return s.logRepo.FindRecent(ctx, limit)
}

// GetLogsCount returns total number of logs
func (s *LogService) GetLogsCount(ctx context.Context) (int64, error) {
	return s.logRepo.Count(ctx)
}

// GetBlockedLogsCount returns total number of blocked logs
func (s *LogService) GetBlockedLogsCount(ctx context.Context) (int64, error) {
	return s.logRepo.CountBlocked(ctx)
}

// CreateLog creates a new log
func (s *LogService) CreateLog(ctx context.Context, log *models.Log) error {
	if log == nil {
		return fmt.Errorf("log cannot be nil")
	}
	return s.logRepo.Create(ctx, log)
}

// UpdateLog updates an existing log
func (s *LogService) UpdateLog(ctx context.Context, log *models.Log) error {
	if log == nil {
		return fmt.Errorf("log cannot be nil")
	}
	if log.ID == 0 {
		return fmt.Errorf("log ID must be set")
	}
	return s.logRepo.Update(ctx, log)
}

// DeleteLog deletes a log
func (s *LogService) DeleteLog(ctx context.Context, id uint) error {
	if id == 0 {
		return fmt.Errorf("log ID must be set")
	}
	return s.logRepo.Delete(ctx, id)
}

// GetPaginatedLogs returns paginated logs
func (s *LogService) GetPaginatedLogs(ctx context.Context, page int, pageSize int) ([]models.Log, int64, error) {
	if page < 1 || pageSize < 1 {
		return nil, 0, fmt.Errorf("page and pageSize must be positive")
	}
	offset := (page - 1) * pageSize
	return s.logRepo.FindPaginated(ctx, offset, pageSize)
}

// UpdateLogsByIPAndDescription updates logs matching IP and description
func (s *LogService) UpdateLogsByIPAndDescription(ctx context.Context, ip string, description string, updates map[string]interface{}) error {
	if ip == "" || description == "" {
		return fmt.Errorf("IP and description cannot be empty")
	}
	if len(updates) == 0 {
		return fmt.Errorf("updates cannot be empty")
	}
	return s.logRepo.UpdateByIPAndDescription(ctx, ip, description, updates)
}
