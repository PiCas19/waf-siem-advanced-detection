package rules

import (
	"encoding/json"
	"testing"

	"github.com/PiCas19/waf-siem-advanced-detection/waf/internal/rules"
	"gopkg.in/yaml.v3"
)

func TestRule_Structure(t *testing.T) {
	rule := rules.Rule{
		ID:          "rule-001",
		Name:        "Test Rule",
		Description: "This is a test rule",
		Severity:    "HIGH",
		Patterns:    []string{"pattern1", "pattern2"},
		Enabled:     true,
		Actions:     []string{"block", "log"},
	}

	if rule.ID != "rule-001" {
		t.Errorf("Expected ID to be 'rule-001', got %s", rule.ID)
	}
	if rule.Name != "Test Rule" {
		t.Errorf("Expected Name to be 'Test Rule', got %s", rule.Name)
	}
	if rule.Severity != "HIGH" {
		t.Errorf("Expected Severity to be 'HIGH', got %s", rule.Severity)
	}
	if !rule.Enabled {
		t.Error("Expected Enabled to be true")
	}
	if len(rule.Patterns) != 2 {
		t.Errorf("Expected 2 patterns, got %d", len(rule.Patterns))
	}
	if len(rule.Actions) != 2 {
		t.Errorf("Expected 2 actions, got %d", len(rule.Actions))
	}
}

func TestRule_YAMLMarshaling(t *testing.T) {
	rule := rules.Rule{
		ID:          "rule-002",
		Name:        "SQLi Detection",
		Description: "Detects SQL injection attempts",
		Severity:    "CRITICAL",
		Patterns:    []string{"union.*select", "or.*1=1"},
		Enabled:     true,
		Actions:     []string{"block", "alert"},
	}

	// Marshal to YAML
	data, err := yaml.Marshal(rule)
	if err != nil {
		t.Fatalf("Failed to marshal rule to YAML: %v", err)
	}

	// Unmarshal back
	var unmarshaled rules.Rule
	err = yaml.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Fatalf("Failed to unmarshal YAML to rule: %v", err)
	}

	// Verify fields
	if unmarshaled.ID != rule.ID {
		t.Errorf("Expected ID %s, got %s", rule.ID, unmarshaled.ID)
	}
	if unmarshaled.Name != rule.Name {
		t.Errorf("Expected Name %s, got %s", rule.Name, unmarshaled.Name)
	}
	if unmarshaled.Severity != rule.Severity {
		t.Errorf("Expected Severity %s, got %s", rule.Severity, unmarshaled.Severity)
	}
	if len(unmarshaled.Patterns) != len(rule.Patterns) {
		t.Errorf("Expected %d patterns, got %d", len(rule.Patterns), len(unmarshaled.Patterns))
	}
	if len(unmarshaled.Actions) != len(rule.Actions) {
		t.Errorf("Expected %d actions, got %d", len(rule.Actions), len(unmarshaled.Actions))
	}
}

func TestRule_JSONMarshaling(t *testing.T) {
	rule := rules.Rule{
		ID:          "rule-003",
		Name:        "XSS Detection",
		Description: "Detects cross-site scripting",
		Severity:    "MEDIUM",
		Patterns:    []string{"<script", "javascript:"},
		Enabled:     false,
		Actions:     []string{"log"},
	}

	// Marshal to JSON
	data, err := json.Marshal(rule)
	if err != nil {
		t.Fatalf("Failed to marshal rule to JSON: %v", err)
	}

	// Unmarshal back
	var unmarshaled rules.Rule
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Fatalf("Failed to unmarshal JSON to rule: %v", err)
	}

	// Verify fields
	if unmarshaled.ID != rule.ID {
		t.Errorf("Expected ID %s, got %s", rule.ID, unmarshaled.ID)
	}
	if unmarshaled.Enabled != rule.Enabled {
		t.Errorf("Expected Enabled %v, got %v", rule.Enabled, unmarshaled.Enabled)
	}
	if len(unmarshaled.Patterns) != len(rule.Patterns) {
		t.Errorf("Expected %d patterns, got %d", len(rule.Patterns), len(unmarshaled.Patterns))
	}
}

func TestRule_SeverityLevels(t *testing.T) {
	testCases := []struct {
		name     string
		severity string
	}{
		{"Low severity", "LOW"},
		{"Medium severity", "MEDIUM"},
		{"High severity", "HIGH"},
		{"Critical severity", "CRITICAL"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rule := rules.Rule{
				ID:       "test-" + tc.severity,
				Severity: tc.severity,
				Enabled:  true,
			}

			if rule.Severity != tc.severity {
				t.Errorf("Expected Severity %s, got %s", tc.severity, rule.Severity)
			}
		})
	}
}

func TestRule_MultiplePatterns(t *testing.T) {
	patterns := []string{
		"pattern1",
		"pattern2",
		"pattern3",
		"pattern4",
		"pattern5",
	}

	rule := rules.Rule{
		ID:       "multi-pattern",
		Patterns: patterns,
		Enabled:  true,
	}

	if len(rule.Patterns) != 5 {
		t.Errorf("Expected 5 patterns, got %d", len(rule.Patterns))
	}

	for i, pattern := range rule.Patterns {
		if pattern != patterns[i] {
			t.Errorf("Pattern %d: expected %s, got %s", i, patterns[i], pattern)
		}
	}
}

func TestRule_MultipleActions(t *testing.T) {
	actions := []string{"block", "log", "alert"}

	rule := rules.Rule{
		ID:      "multi-action",
		Actions: actions,
		Enabled: true,
	}

	if len(rule.Actions) != 3 {
		t.Errorf("Expected 3 actions, got %d", len(rule.Actions))
	}

	for i, action := range rule.Actions {
		if action != actions[i] {
			t.Errorf("Action %d: expected %s, got %s", i, actions[i], action)
		}
	}
}

func TestRule_EmptyRule(t *testing.T) {
	rule := rules.Rule{}

	if rule.ID != "" {
		t.Errorf("Expected empty ID, got %s", rule.ID)
	}
	if rule.Enabled {
		t.Error("Expected Enabled to be false by default")
	}
	if len(rule.Patterns) != 0 {
		t.Errorf("Expected 0 patterns, got %d", len(rule.Patterns))
	}
	if len(rule.Actions) != 0 {
		t.Errorf("Expected 0 actions, got %d", len(rule.Actions))
	}
}

func TestRule_DisabledRule(t *testing.T) {
	rule := rules.Rule{
		ID:       "disabled-rule",
		Name:     "Disabled Test Rule",
		Severity: "LOW",
		Enabled:  false,
		Actions:  []string{"log"},
	}

	if rule.Enabled {
		t.Error("Expected rule to be disabled")
	}
}
