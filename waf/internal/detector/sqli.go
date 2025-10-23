package detector

import (
	"regexp"
	"strings"
)

// SQLiDetector detects SQL Injection attacks
type SQLiDetector struct {
	patterns []*regexp.Regexp
}

// NewSQLiDetector creates a new SQL injection detector
func NewSQLiDetector() *SQLiDetector {
	patterns := []string{
		// Union-based SQLi
		`(?i)(union\s+(all\s+)?select)`,
		
		// Boolean-based SQLi
		`(?i)(or\s+1\s*=\s*1)`,
		`(?i)(and\s+1\s*=\s*1)`,
		`(?i)(or\s+'1'\s*=\s*'1)`,
		`(?i)(and\s+'1'\s*=\s*'1)`,
		`(?i)(or\s+"1"\s*=\s*"1)`,
		
		// Comments
		`(--|#|/\*|\*/)`,
		
		// SQL keywords
		`(?i)\b(select|insert|update|delete|drop|create|alter|exec|execute)\b.*\b(from|into|table|database)\b`,
		
		// Stacked queries
		`;\s*(drop|delete|update|insert)`,
		
		// Time-based blind SQLi
		`(?i)(sleep\s*\(|benchmark\s*\(|waitfor\s+delay)`,
		
		// SQL functions
		`(?i)(concat\s*\(|char\s*\(|ascii\s*\(|substring\s*\()`,
		
		// Information schema
		`(?i)information_schema`,
		
		// SQL wildcards
		`(?i)(having|group\s+by|order\s+by)`,
		
		// Quotes and escape sequences
		`'.*?--`,
		`".*?--`,
		`\\x[0-9a-f]{2}`,
	}
	
	compiled := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		compiled[i] = regexp.MustCompile(p)
	}
	
	return &SQLiDetector{patterns: compiled}
}

// Detect checks if input contains SQL injection patterns
func (d *SQLiDetector) Detect(input string) (bool, string) {
	// Normalize input
	normalized := strings.ToLower(strings.TrimSpace(input))
	
	// Remove common whitespace variations
	normalized = regexp.MustCompile(`\s+`).ReplaceAllString(normalized, " ")
	
	for _, pattern := range d.patterns {
		if pattern.MatchString(normalized) {
			return true, "SQL Injection pattern detected: " + pattern.String()
		}
	}
	
	return false, ""
}