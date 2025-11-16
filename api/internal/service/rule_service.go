package service

import (
	"context"
	"fmt"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/repository"
)

// RuleService handles business logic for WAF rules
type RuleService struct {
	ruleRepo repository.RuleRepository
}

// NewRuleService creates a new rule service
func NewRuleService(ruleRepo repository.RuleRepository) *RuleService {
	return &RuleService{
		ruleRepo: ruleRepo,
	}
}

// GetAllRules retrieves all rules
func (s *RuleService) GetAllRules(ctx context.Context) ([]models.Rule, error) {
	return s.ruleRepo.FindAll(ctx)
}

// GetRuleByID retrieves a rule by ID
func (s *RuleService) GetRuleByID(ctx context.Context, id uint) (*models.Rule, error) {
	rule, err := s.ruleRepo.FindByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get rule: %w", err)
	}
	if rule == nil {
		return nil, fmt.Errorf("rule not found")
	}
	return rule, nil
}

// GetEnabledRules retrieves all enabled rules
func (s *RuleService) GetEnabledRules(ctx context.Context) ([]models.Rule, error) {
	return s.ruleRepo.FindEnabled(ctx)
}

// GetRulesByType retrieves rules by threat type
func (s *RuleService) GetRulesByType(ctx context.Context, threatType string) ([]models.Rule, error) {
	if threatType == "" {
		return nil, fmt.Errorf("threat type cannot be empty")
	}
	return s.ruleRepo.FindByType(ctx, threatType)
}

// GetRulesCount returns total number of rules
func (s *RuleService) GetRulesCount(ctx context.Context) (int64, error) {
	return s.ruleRepo.Count(ctx)
}

// CreateRule creates a new rule
func (s *RuleService) CreateRule(ctx context.Context, rule *models.Rule) error {
	if rule == nil {
		return fmt.Errorf("rule cannot be nil")
	}
	if rule.Name == "" {
		return fmt.Errorf("rule name cannot be empty")
	}
	if rule.Pattern == "" {
		return fmt.Errorf("rule pattern cannot be empty")
	}
	if rule.Type == "" {
		return fmt.Errorf("rule type cannot be empty")
	}
	return s.ruleRepo.Create(ctx, rule)
}

// UpdateRule updates an existing rule
func (s *RuleService) UpdateRule(ctx context.Context, rule *models.Rule) error {
	if rule == nil {
		return fmt.Errorf("rule cannot be nil")
	}
	if rule.ID == 0 {
		return fmt.Errorf("rule ID must be set")
	}
	return s.ruleRepo.Update(ctx, rule)
}

// DeleteRule deletes a rule
func (s *RuleService) DeleteRule(ctx context.Context, id uint) error {
	if id == 0 {
		return fmt.Errorf("rule ID must be set")
	}
	return s.ruleRepo.Delete(ctx, id)
}

// ToggleRuleEnabled enables/disables a rule
func (s *RuleService) ToggleRuleEnabled(ctx context.Context, id uint, enabled bool) error {
	if id == 0 {
		return fmt.Errorf("rule ID must be set")
	}
	return s.ruleRepo.ToggleEnabled(ctx, id, enabled)
}

// EnableRule enables a rule
func (s *RuleService) EnableRule(ctx context.Context, id uint) error {
	return s.ToggleRuleEnabled(ctx, id, true)
}

// DisableRule disables a rule
func (s *RuleService) DisableRule(ctx context.Context, id uint) error {
	return s.ToggleRuleEnabled(ctx, id, false)
}
