package detector

import (
	"regexp"
	"strings"
)

type SQLiDetector struct {
	patterns []*regexp.Regexp
}

func NewSQLiDetector() *SQLiDetector {
	patterns := []string{
		`(?i)(union\s+(all\s+)?select)`,
		`(?i)(or\s+1\s*=\s*1)`,
		`(?i)(and\s+1\s*=\s*1)`,
		`(?i)(or\s+'1'\s*=\s*'1)`,
		`(?i)(and\s+'1'\s*=\s*'1)`,
		`(--|#|/\*|\*/)`,
		`(?i)\b(select|insert|update|delete|drop|create|alter|exec)\b.*\b(from|into|table|database)\b`,
		`;\s*(drop|delete|update|insert)`,
		`(?i)(sleep\s*\(|benchmark\s*\(|waitfor\s+delay)`,
		`(?i)(concat\s*\(|char\s*\(|ascii\s*\(|substring\s*\()`,
		`(?i)information_schema`,
		`(?i)(having|group\s+by|order\s+by)`,
	}
	
	compiled := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		compiled[i] = regexp.MustCompile(p)
	}
	
	return &SQLiDetector{patterns: compiled}
}

func (d *SQLiDetector) Detect(input string) (bool, string) {
	normalized := strings.ToLower(strings.TrimSpace(input))
	normalized = regexp.MustCompile(`\s+`).ReplaceAllString(normalized, " ")
	
	for _, pattern := range d.patterns {
		if pattern.MatchString(normalized) {
			return true, "SQL Injection pattern detected"
		}
	}
	
	return false, ""
}