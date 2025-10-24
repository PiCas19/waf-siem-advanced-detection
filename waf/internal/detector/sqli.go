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
		// === BOOLEAN-BASED SQLI (MIGLIORATI) ===
		`(?i)\b(or|and)\s*['"]?\s*\d+\s*=\s*\d+['"]?\s*`,           // or 1=1, or "1"="1", or '1'='1'
		`(?i)\b(or|and)\s*['"]1['"]\s*=\s*['"]1['"]\s*`,             // '1'='1', "1"="1"
		`(?i)\b(or|and)\s*['"][^'"]*['"]\s*=\s*['"][^'"]*['"]`,      // 'a'='a' generico

		// === CLASSICI BOOLEANI ===
		`(?i)(or\s+1\s*=\s*1)`,
		`(?i)(and\s+1\s*=\s*1)`,
		`(?i)(or\s+'1'\s*=\s*'1)`,
		`(?i)(and\s+'1'\s*=\s*'1)`,
		`(?i)(or\s+"1"\s*=\s*"1)`,
		`(?i)(and\s+"1"\s*=\s*"1)`,

		// === CON COMMENTI O CHIUSURA STRINGA ===
		`(?i)['"]\s*(or|and)\s*['"]1['"]\s*=\s*['"]1['"]`,           // ' OR '1'='1
		`(?i)['"]\s*(or|and)\s*1=1`,                                 // ' OR 1=1

		// === UNION, COMMENTS, ETC (già presenti) ===
		`(?i)(union\s+(all\s+)?select)`,
		`(--|#|/\*|\*/)`,
		`(?i)\b(select|insert|update|delete|drop|create|alter|exec|execute)\b.*\b(from|into|table|database)\b`,
		`;\s*(drop|delete|update|insert)`,
		`(?i)(sleep\s*\(|benchmark\s*\(|waitfor\s+delay)`,
		`(?i)(concat\s*\(|char\s*\(|ascii\s*\(|substring\s*\()`,
		`(?i)information_schema`,
		`(?i)(having|group\s+by|order\s+by)`,
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