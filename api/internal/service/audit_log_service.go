package service

import (
	"context"
	"fmt"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/repository"
)

// AuditLogService handles business logic for audit logs
type AuditLogService struct {
	auditLogRepo repository.AuditLogRepository
}

// NewAuditLogService creates a new audit log service
func NewAuditLogService(auditLogRepo repository.AuditLogRepository) *AuditLogService {
	return &AuditLogService{
		auditLogRepo: auditLogRepo,
	}
}

// GetAllAuditLogs retrieves all audit logs
func (s *AuditLogService) GetAllAuditLogs(ctx context.Context) ([]models.AuditLog, error) {
	return s.auditLogRepo.FindAll(ctx)
}

// GetAuditLogsByUser retrieves audit logs for a specific user
func (s *AuditLogService) GetAuditLogsByUser(ctx context.Context, userID uint) ([]models.AuditLog, error) {
	if userID == 0 {
		return nil, fmt.Errorf("user ID must be set")
	}
	return s.auditLogRepo.FindByUser(ctx, userID)
}

// GetAuditLogsByAction retrieves audit logs for a specific action
func (s *AuditLogService) GetAuditLogsByAction(ctx context.Context, action string) ([]models.AuditLog, error) {
	if action == "" {
		return nil, fmt.Errorf("action cannot be empty")
	}
	return s.auditLogRepo.FindByAction(ctx, action)
}

// GetRecentAuditLogs retrieves recent audit logs
func (s *AuditLogService) GetRecentAuditLogs(ctx context.Context, limit int) ([]models.AuditLog, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("limit must be positive")
	}
	return s.auditLogRepo.FindRecent(ctx, limit)
}

// GetAuditLogsCount returns total number of audit logs
func (s *AuditLogService) GetAuditLogsCount(ctx context.Context) (int64, error) {
	return s.auditLogRepo.Count(ctx)
}

// GetSuccessfulActionsCount returns count of successful audit logs
func (s *AuditLogService) GetSuccessfulActionsCount(ctx context.Context) (int64, error) {
	return s.auditLogRepo.CountByStatus(ctx, "success")
}

// GetFailedActionsCount returns count of failed audit logs
func (s *AuditLogService) GetFailedActionsCount(ctx context.Context) (int64, error) {
	return s.auditLogRepo.CountByStatus(ctx, "failure")
}

// CreateAuditLog creates a new audit log
func (s *AuditLogService) CreateAuditLog(ctx context.Context, auditLog *models.AuditLog) error {
	if auditLog == nil {
		return fmt.Errorf("audit log cannot be nil")
	}
	if auditLog.UserID == 0 {
		return fmt.Errorf("user ID must be set")
	}
	if auditLog.Action == "" {
		return fmt.Errorf("action cannot be empty")
	}
	return s.auditLogRepo.Create(ctx, auditLog)
}

// GetPaginatedAuditLogs returns paginated audit logs
func (s *AuditLogService) GetPaginatedAuditLogs(ctx context.Context, page int, pageSize int) ([]models.AuditLog, int64, error) {
	if page < 1 || pageSize < 1 {
		return nil, 0, fmt.Errorf("page and pageSize must be positive")
	}
	offset := (page - 1) * pageSize
	return s.auditLogRepo.FindPaginated(ctx, offset, pageSize)
}

// GetActionBreakdown returns statistics on actions
func (s *AuditLogService) GetActionBreakdown(ctx context.Context) (map[string]int64, error) {
	return s.auditLogRepo.GetActionBreakdown(ctx)
}

// LogAction is a convenience method to log an action
func (s *AuditLogService) LogAction(ctx context.Context, userID uint, action string, status string, details string) error {
	auditLog := &models.AuditLog{
		UserID:  userID,
		Action:  action,
		Status:  status,
		Details: details,
	}
	return s.CreateAuditLog(ctx, auditLog)
}

// LogActionSuccess logs a successful action
func (s *AuditLogService) LogActionSuccess(ctx context.Context, userID uint, action string, details string) error {
	return s.LogAction(ctx, userID, action, "success", details)
}

// LogActionFailure logs a failed action
func (s *AuditLogService) LogActionFailure(ctx context.Context, userID uint, action string, details string) error {
	return s.LogAction(ctx, userID, action, "failure", details)
}
