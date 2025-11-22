package detector

import (
	"regexp"
	"sync"
)

// CustomRule represents a rule loaded from the database
type CustomRule struct {
	ID                uint
	Name              string
	Pattern           string
	Type              string
	Severity          string
	Enabled           bool
	Action            string // "log" or "block"
	BlockEnabled      bool   // True if block action is selected
	DropEnabled       bool   // True if drop action is selected
	RedirectEnabled   bool   // True if redirect action is selected
	ChallengeEnabled  bool   // True if challenge action is selected
	RedirectURL       string // URL to redirect to (if RedirectEnabled is true)
	IsManualBlock     bool   // True if created by manual threat blocking - has priority over "log-only" detected rules
	regex             *regexp.Regexp
}

// CustomRuleDetector manages detection using custom rules from database
type CustomRuleDetector struct {
	mu    sync.RWMutex
	rules []*CustomRule
}

// NewCustomRuleDetector creates a new custom rule detector
func NewCustomRuleDetector() *CustomRuleDetector {
	return &CustomRuleDetector{
		rules: make([]*CustomRule, 0),
	}
}

// UpdateRules updates the custom rules (called when rules change)
func (crd *CustomRuleDetector) UpdateRules(rules []*CustomRule) error {
	crd.mu.Lock()
	defer crd.mu.Unlock()

	// Compile all regex patterns
	for _, rule := range rules {
		if rule.Enabled {
			compiled, err := regexp.Compile(rule.Pattern)
			if err != nil {
				return err
			}
			rule.regex = compiled
		}
	}

	crd.rules = rules
	return nil
}

// DetectBlocked checks if a value matches any CUSTOM RULE with action="block" (PRIORITY 2)
// These are custom rules that have blocking enabled
func (crd *CustomRuleDetector) DetectBlocked(value string) (matched *CustomRule) {
	crd.mu.RLock()
	defer crd.mu.RUnlock()

	for _, rule := range crd.rules {
		// Skip manual block rules and disabled rules
		if !rule.Enabled || rule.IsManualBlock {
			continue
		}
		// Only return rules with action="block" (not "log")
		if rule.Action != "block" {
			continue
		}
		if rule.regex != nil && rule.regex.MatchString(value) {
			return rule
		}
	}
	return nil
}

// DetectManualBlock checks if a value matches any MANUAL BLOCK custom rule (PRIORITY 3)
// Manual block rules created by user from dashboard BLOCK action
func (crd *CustomRuleDetector) DetectManualBlock(value string) (matched *CustomRule) {
	crd.mu.RLock()
	defer crd.mu.RUnlock()

	for _, rule := range crd.rules {
		if !rule.Enabled || !rule.IsManualBlock {
			continue
		}
		if rule.regex != nil && rule.regex.MatchString(value) {
			return rule
		}
	}
	return nil
}

// DetectDetected checks if a value matches any CUSTOM RULE with action="log" (PRIORITY 4)
// These are custom rules that only detect/log, not block
func (crd *CustomRuleDetector) DetectDetected(value string) (matched *CustomRule) {
	crd.mu.RLock()
	defer crd.mu.RUnlock()

	for _, rule := range crd.rules {
		// Skip manual block rules and disabled rules
		if !rule.Enabled || rule.IsManualBlock {
			continue
		}
		// Only return rules with action="log" (not "block")
		if rule.Action != "log" {
			continue
		}
		if rule.regex != nil && rule.regex.MatchString(value) {
			return rule
		}
	}
	return nil
}

// Detect checks if a value matches any custom rule (DEPRECATED - use specific methods instead)
func (crd *CustomRuleDetector) Detect(value string) (matched *CustomRule) {
	crd.mu.RLock()
	defer crd.mu.RUnlock()

	for _, rule := range crd.rules {
		if !rule.Enabled || rule.IsManualBlock {
			continue
		}
		if rule.regex != nil && rule.regex.MatchString(value) {
			return rule
		}
	}
	return nil
}

// GetRules returns a copy of current rules
func (crd *CustomRuleDetector) GetRules() []*CustomRule {
	crd.mu.RLock()
	defer crd.mu.RUnlock()

	result := make([]*CustomRule, len(crd.rules))
	copy(result, crd.rules)
	return result
}
