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
		// Union-based (UNION + SELECT insieme)
		`(?i)union\s+(all\s+)?select\s+`,
		
		// Boolean-based COMPLETI
		`(?i)'\s*or\s+'1'\s*=\s*'1`,
		`(?i)"\s*or\s+"1"\s*=\s*"1`,
		`(?i)'\s*or\s+1\s*=\s*1`,
		`(?i)'\s*and\s+'1'\s*=\s*'1`,
		`(?i)\bor\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?\s*(--|#|/\*)`,
		
		// SQL comments DOPO apici
		`'\s*--`,
		`'\s*#`,
		`'\s*/\*`,
		`"\s*--`,
		
		// Stacked queries (; + comando SQL)
		`;\s*(drop|delete|update|insert|exec|execute)\s+(table|database|into)`,
		
		// Time-based blind CON NUMERI
		`(?i)sleep\s*\(\s*\d+\s*\)`,
		`(?i)benchmark\s*\(\s*\d+\s*,`,
		`(?i)waitfor\s+delay\s+['"]0:0:\d`,
		`(?i)pg_sleep\s*\(\s*\d+\s*\)`,
		
		// Information schema COMPLETO
		`(?i)information_schema\.(tables|columns|schemata)`,
		`(?i)from\s+information_schema`,
		
		// SELECT FROM insieme
		`(?i)select\s+.*\s+from\s+`,
		
		// Classic authentication bypass
		`(?i)admin'\s*--`,
		`(?i)admin'\s*#`,
		`(?i)'\s*or\s*'.*'\s*=\s*'`,
		
		// UNION con NULL
		`(?i)union.*select.*null`,
		
		// Dangerous functions CON parametri SQL
		`(?i)load_file\s*\(`,
		`(?i)into\s+outfile\s+`,
		`(?i)into\s+dumpfile\s+`,
	}
	
	compiled := make([]*regexp.Regexp, 0)
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err == nil {
			compiled = append(compiled, re)
		}
	}
	
	return &SQLiDetector{patterns: compiled}
}

func (d *SQLiDetector) Detect(input string) (bool, string) {
	// Ignora input molto corti
	if len(input) < 4 {
		return false, ""
	}
	
	// Ignora numeri puri e parole singole
	if regexp.MustCompile(`^[0-9]+$`).MatchString(input) {
		return false, ""
	}
	if regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]*$`).MatchString(input) && len(input) < 20 {
		return false, ""
	}
	
	// Normalize
	normalized := strings.ToLower(strings.TrimSpace(input))
	normalized = regexp.MustCompile(`\s+`).ReplaceAllString(normalized, " ")
	
	// Check solo se contiene indicatori SQL
	if !strings.Contains(normalized, "'") && 
	   !strings.Contains(normalized, "union") && 
	   !strings.Contains(normalized, "select") && 
	   !strings.Contains(normalized, "--") &&
	   !strings.Contains(normalized, "sleep") {
		return false, ""
	}
	
	for _, pattern := range d.patterns {
		if pattern.MatchString(normalized) {
			return true, "SQL Injection pattern detected"
		}
	}
	
	return false, ""
}
