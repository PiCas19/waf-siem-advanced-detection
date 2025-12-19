package detector_test

import (
	"testing"

	"github.com/PiCas19/waf-siem-advanced-detection/waf/internal/detector"
)

func TestCustomRuleDetector(t *testing.T) {
	// Creazione del detector
	crd := detector.NewCustomRuleDetector()

	// Definizione delle regole di test
	rules := []*detector.CustomRule{
		{
			ID:               1,
			Name:             "Block Admin Access",
			Pattern:          `(?i)admin`,
			Type:             "CUSTOM",
			Severity:         "HIGH",
			Enabled:          true,
			Action:           "block",
			BlockEnabled:     true,
			DropEnabled:      false,
			RedirectEnabled:  false,
			ChallengeEnabled: false,
			IsManualBlock:    false,
		},
		{
			ID:               2,
			Name:             "Detect Credit Card",
			Pattern:          `\b(?:\d[ -]*?){13,16}\b`,
			Type:             "CUSTOM",
			Severity:         "MEDIUM",
			Enabled:          true,
			Action:           "log",
			BlockEnabled:     false,
			DropEnabled:      false,
			RedirectEnabled:  false,
			ChallengeEnabled: false,
			IsManualBlock:    false,
		},
		{
			ID:               3,
			Name:             "Manual Block IP",
			Pattern:          `192\.168\.1\.100`,
			Type:             "IP_BLOCK",
			Severity:         "CRITICAL",
			Enabled:          true,
			Action:           "block",
			BlockEnabled:     true,
			DropEnabled:      false,
			RedirectEnabled:  false,
			ChallengeEnabled: false,
			IsManualBlock:    true,
		},
		{
			ID:               4,
			Name:             "Disabled Rule",
			Pattern:          `disabled`,
			Type:             "CUSTOM",
			Severity:         "LOW",
			Enabled:          false,
			Action:           "block",
			BlockEnabled:     true,
			DropEnabled:      false,
			RedirectEnabled:  false,
			ChallengeEnabled: false,
			IsManualBlock:    false,
		},
	}

	// Aggiornamento delle regole
	err := crd.UpdateRules(rules)
	if err != nil {
		t.Fatalf("Failed to update rules: %v", err)
	}

	tests := []struct {
		name         string
		input        string
		method       string
		expectedID   uint
		expectedType string
	}{
		// PRIORITY 2: Custom rules with action="block"
		{
			name:         "Block rule detection",
			input:        "user=admin",
			method:       "DetectBlocked",
			expectedID:   1,
			expectedType: "CUSTOM",
		},
		{
			name:         "Block rule not matching",
			input:        "user=guest",
			method:       "DetectBlocked",
			expectedID:   0,
			expectedType: "",
		},
		// PRIORITY 3: Manual block rules
		{
			name:         "Manual block detection",
			input:        "192.168.1.100",
			method:       "DetectManualBlock",
			expectedID:   3,
			expectedType: "IP_BLOCK",
		},
		// PRIORITY 4: Detect-only rules
		{
			name:         "Detect-only rule",
			input:        "4111-1111-1111-1111",
			method:       "DetectDetected",
			expectedID:   2,
			expectedType: "CUSTOM",
		},
		// Disabled rule should not match
		{
			name:         "Disabled rule",
			input:        "disabled-pattern",
			method:       "DetectBlocked",
			expectedID:   0,
			expectedType: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rule *detector.CustomRule
			
			switch tt.method {
			case "DetectBlocked":
				rule = crd.DetectBlocked(tt.input)
			case "DetectManualBlock":
				rule = crd.DetectManualBlock(tt.input)
			case "DetectDetected":
				rule = crd.DetectDetected(tt.input)
			case "Detect":
				rule = crd.Detect(tt.input)
			}

			if tt.expectedID == 0 {
				if rule != nil {
					t.Errorf("Expected no rule match, but got rule ID %d", rule.ID)
				}
			} else {
				if rule == nil {
					t.Errorf("Expected rule ID %d, but got nil", tt.expectedID)
				} else if rule.ID != tt.expectedID {
					t.Errorf("Expected rule ID %d, got %d", tt.expectedID, rule.ID)
				}
				if rule.Type != tt.expectedType {
					t.Errorf("Expected rule type %s, got %s", tt.expectedType, rule.Type)
				}
			}
		})
	}

	// Test GetRules
	t.Run("GetRules returns copy", func(t *testing.T) {
		rulesCopy := crd.GetRules()
		if len(rulesCopy) != len(rules) {
			t.Errorf("Expected %d rules, got %d", len(rules), len(rulesCopy))
		}
	})

	// Test invalid regex pattern
	t.Run("Invalid regex pattern", func(t *testing.T) {
		invalidRules := []*detector.CustomRule{
			{
				ID:       5,
				Name:     "Invalid Regex",
				Pattern:  `[invalid[regex`,
				Enabled:  true,
				Action:   "block",
			},
		}
		
		err := crd.UpdateRules(invalidRules)
		if err == nil {
			t.Error("Expected error for invalid regex, got nil")
		}
	})
}