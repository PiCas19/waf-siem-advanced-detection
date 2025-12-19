package rules

import (
	"testing"

	"github.com/PiCas19/waf-siem-advanced-detection/waf/internal/rules"
)

func TestNewRuleEngine(t *testing.T) {
	rulesList := []rules.Rule{
		{
			ID:       "rule-001",
			Name:     "SQLi Detection",
			Severity: "HIGH",
			Patterns: []string{"union.*select", "or.*1=1"},
			Enabled:  true,
			Actions:  []string{"block"},
		},
		{
			ID:       "rule-002",
			Name:     "XSS Detection",
			Severity: "MEDIUM",
			Patterns: []string{"<script", "javascript:"},
			Enabled:  true,
			Actions:  []string{"log"},
		},
	}

	engine := rules.NewRuleEngine(rulesList)
	if engine == nil {
		t.Fatal("Expected non-nil engine")
	}
}

func TestNewRuleEngine_DisabledRules(t *testing.T) {
	rulesList := []rules.Rule{
		{
			ID:       "enabled-rule",
			Patterns: []string{"pattern1"},
			Enabled:  true,
		},
		{
			ID:       "disabled-rule",
			Patterns: []string{"pattern2"},
			Enabled:  false,
		},
	}

	engine := rules.NewRuleEngine(rulesList)

	// Test that disabled rule doesn't match
	result := engine.Match("pattern2")
	if result != nil {
		t.Error("Disabled rule should not match")
	}

	// Test that enabled rule matches
	result = engine.Match("pattern1")
	if result == nil {
		t.Error("Enabled rule should match")
	}
}

func TestRuleEngine_Match_SQLi(t *testing.T) {
	rulesList := []rules.Rule{
		{
			ID:       "sqli-rule",
			Name:     "SQL Injection",
			Severity: "HIGH",
			Patterns: []string{"union.*select", "or.*1=1", `drop.*table`},
			Enabled:  true,
			Actions:  []string{"block"},
		},
	}

	engine := rules.NewRuleEngine(rulesList)

	testCases := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "UNION SELECT attack",
			input:    "1' UNION SELECT * FROM users--",
			expected: true,
		},
		{
			name:     "OR 1=1 attack",
			input:    "admin' OR 1=1--",
			expected: true,
		},
		{
			name:     "DROP TABLE attack",
			input:    "'; DROP TABLE users;--",
			expected: true,
		},
		{
			name:     "Case insensitive match",
			input:    "UNION select password from users",
			expected: true,
		},
		{
			name:     "Normal query",
			input:    "SELECT * FROM products WHERE id=1",
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := engine.Match(tc.input)
			if tc.expected && result == nil {
				t.Errorf("Expected match for input: %s", tc.input)
			}
			if !tc.expected && result != nil {
				t.Errorf("Expected no match for input: %s", tc.input)
			}
			if tc.expected && result != nil {
				if result.ID != "sqli-rule" {
					t.Errorf("Expected rule ID 'sqli-rule', got %s", result.ID)
				}
			}
		})
	}
}

func TestRuleEngine_Match_XSS(t *testing.T) {
	rulesList := []rules.Rule{
		{
			ID:       "xss-rule",
			Name:     "XSS Detection",
			Severity: "MEDIUM",
			Patterns: []string{"<script", "javascript:", "onerror=", "onload="},
			Enabled:  true,
			Actions:  []string{"block", "log"},
		},
	}

	engine := rules.NewRuleEngine(rulesList)

	testCases := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "Script tag",
			input:    "<script>alert('XSS')</script>",
			expected: true,
		},
		{
			name:     "JavaScript protocol",
			input:    `<a href="javascript:alert('XSS')">Click</a>`,
			expected: true,
		},
		{
			name:     "Onerror event",
			input:    `<img src=x onerror=alert('XSS')>`,
			expected: true,
		},
		{
			name:     "Onload event",
			input:    `<body onload=alert('XSS')>`,
			expected: true,
		},
		{
			name:     "Normal HTML",
			input:    "<div>Hello World</div>",
			expected: false,
		},
		{
			name:     "Normal text",
			input:    "This is a normal comment",
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := engine.Match(tc.input)
			if tc.expected && result == nil {
				t.Errorf("Expected match for input: %s", tc.input)
			}
			if !tc.expected && result != nil {
				t.Errorf("Expected no match for input: %s", tc.input)
			}
		})
	}
}

func TestRuleEngine_Match_MultipleRules(t *testing.T) {
	rulesList := []rules.Rule{
		{
			ID:       "sqli-rule",
			Severity: "HIGH",
			Patterns: []string{"union.*select"},
			Enabled:  true,
		},
		{
			ID:       "xss-rule",
			Severity: "MEDIUM",
			Patterns: []string{"<script"},
			Enabled:  true,
		},
		{
			ID:       "lfi-rule",
			Severity: "HIGH",
			Patterns: []string{`\.\./`},
			Enabled:  true,
		},
	}

	engine := rules.NewRuleEngine(rulesList)

	// Test SQLi match
	result := engine.Match("1' UNION SELECT * FROM users")
	if result == nil || result.ID != "sqli-rule" {
		t.Error("Expected sqli-rule to match")
	}

	// Test XSS match
	result = engine.Match("<script>alert(1)</script>")
	if result == nil || result.ID != "xss-rule" {
		t.Error("Expected xss-rule to match")
	}

	// Test LFI match
	result = engine.Match("../../etc/passwd")
	if result == nil || result.ID != "lfi-rule" {
		t.Error("Expected lfi-rule to match")
	}

	// Test no match
	result = engine.Match("normal text")
	if result != nil {
		t.Error("Expected no match for normal text")
	}
}

func TestRuleEngine_Match_CaseInsensitive(t *testing.T) {
	rulesList := []rules.Rule{
		{
			ID:       "case-test",
			Patterns: []string{"select"},
			Enabled:  true,
		},
	}

	engine := rules.NewRuleEngine(rulesList)

	testCases := []string{
		"select",
		"SELECT",
		"SeLeCt",
		"SELECTSELECT",
		"select from users",
	}

	for _, input := range testCases {
		result := engine.Match(input)
		if result == nil {
			t.Errorf("Expected case-insensitive match for: %s", input)
		}
	}
}

func TestRuleEngine_Match_EmptyInput(t *testing.T) {
	rulesList := []rules.Rule{
		{
			ID:       "test-rule",
			Patterns: []string{"pattern"},
			Enabled:  true,
		},
	}

	engine := rules.NewRuleEngine(rulesList)

	result := engine.Match("")
	if result != nil {
		t.Error("Expected no match for empty input")
	}
}

func TestRuleEngine_Match_NoRules(t *testing.T) {
	engine := rules.NewRuleEngine([]rules.Rule{})

	result := engine.Match("any input")
	if result != nil {
		t.Error("Expected no match when engine has no rules")
	}
}

func TestRuleEngine_Match_MultiplePatterns(t *testing.T) {
	rulesList := []rules.Rule{
		{
			ID: "multi-pattern",
			Patterns: []string{
				"pattern1",
				"pattern2",
				"pattern3",
			},
			Enabled: true,
		},
	}

	engine := rules.NewRuleEngine(rulesList)

	// Test each pattern
	for i, pattern := range []string{"pattern1", "pattern2", "pattern3"} {
		result := engine.Match(pattern)
		if result == nil {
			t.Errorf("Pattern %d should match", i+1)
		}
	}

	// Test non-matching
	result := engine.Match("pattern4")
	if result != nil {
		t.Error("pattern4 should not match")
	}
}

func TestRuleEngine_Match_ComplexRegex(t *testing.T) {
	rulesList := []rules.Rule{
		{
			ID: "complex-regex",
			Patterns: []string{
				`\b(union|select|insert|update|delete|drop)\b.*\b(from|into|table)\b`,
				`<(script|iframe|object|embed).*>`,
			},
			Enabled: true,
		},
	}

	engine := rules.NewRuleEngine(rulesList)

	testCases := []struct {
		input    string
		expected bool
	}{
		{"SELECT * FROM users", true},
		{"INSERT INTO table VALUES", true},
		{"UPDATE users SET password", false}, // "table" missing
		{"<script src=x>", true},
		{"<iframe src=evil>", true},
		{"<div>text</div>", false},
	}

	for _, tc := range testCases {
		result := engine.Match(tc.input)
		matched := result != nil
		if matched != tc.expected {
			t.Errorf("Input '%s': expected match=%v, got match=%v", tc.input, tc.expected, matched)
		}
	}
}

func TestRuleEngine_Match_Priority(t *testing.T) {
	rulesList := []rules.Rule{
		{
			ID:       "high-priority",
			Severity: "HIGH",
			Patterns: []string{"attack"},
			Enabled:  true,
		},
		{
			ID:       "low-priority",
			Severity: "LOW",
			Patterns: []string{"attack"},
			Enabled:  true,
		},
	}

	engine := rules.NewRuleEngine(rulesList)

	// Should match the first rule (order matters)
	result := engine.Match("attack")
	if result == nil {
		t.Fatal("Expected a match")
	}

	if result.ID != "high-priority" {
		t.Errorf("Expected first rule to match, got %s", result.ID)
	}
}

func BenchmarkRuleEngine_Match_SingleRule(b *testing.B) {
	rulesList := []rules.Rule{
		{
			ID:       "bench-rule",
			Patterns: []string{"select.*from"},
			Enabled:  true,
		},
	}

	engine := rules.NewRuleEngine(rulesList)
	input := "SELECT * FROM users WHERE id=1"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.Match(input)
	}
}

func BenchmarkRuleEngine_Match_MultipleRules(b *testing.B) {
	rulesList := []rules.Rule{
		{ID: "rule1", Patterns: []string{"pattern1"}, Enabled: true},
		{ID: "rule2", Patterns: []string{"pattern2"}, Enabled: true},
		{ID: "rule3", Patterns: []string{"pattern3"}, Enabled: true},
		{ID: "rule4", Patterns: []string{"pattern4"}, Enabled: true},
		{ID: "rule5", Patterns: []string{"pattern5"}, Enabled: true},
	}

	engine := rules.NewRuleEngine(rulesList)
	input := "this contains pattern3 in the middle"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.Match(input)
	}
}

func BenchmarkRuleEngine_Match_NoMatch(b *testing.B) {
	rulesList := []rules.Rule{
		{ID: "rule1", Patterns: []string{"attack1"}, Enabled: true},
		{ID: "rule2", Patterns: []string{"attack2"}, Enabled: true},
		{ID: "rule3", Patterns: []string{"attack3"}, Enabled: true},
	}

	engine := rules.NewRuleEngine(rulesList)
	input := "normal text without any attacks"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.Match(input)
	}
}
