package tests

import (
	"caddy-waf-project/waf/internal/rules"
	"testing"
)

func TestRuleEngine(t *testing.T) {
	rules := []rules.Rule{
		{Patterns: []string{"test"}, Enabled: true},
	}
	engine := rules.NewRuleEngine(rules)
	if engine.Match("test") == nil {
		t.Errorf("Rule not matched")
	}
}