package rules

import (
	"regexp"
	"strings"
)

type RuleEngine struct {
	rules []*compiledRule
}

type compiledRule struct {
	Rule    Rule
	regexps []*regexp.Regexp
}

func NewRuleEngine(rules []Rule) *RuleEngine {
	engine := &RuleEngine{}
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		cr := &compiledRule{Rule: r}
		for _, p := range r.Patterns {
			re := regexp.MustCompile(`(?i)` + p)
			cr.regexps = append(cr.regexps, re)
		}
		engine.rules = append(engine.rules, cr)
	}
	return engine
}

func (e *RuleEngine) Match(input string) *Rule {
	normalized := strings.ToLower(input)
	for _, cr := range e.rules {
		for _, re := range cr.regexps {
			if re.MatchString(normalized) {
				return &cr.Rule
			}
		}
	}
	return nil
}