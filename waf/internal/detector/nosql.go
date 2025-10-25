package detector

import (
	"regexp"
	"strings"
)

type NoSQLInjectionDetector struct {
	patterns []*regexp.Regexp
}

func NewNoSQLInjectionDetector() *NoSQLInjectionDetector {
	patterns := []string{
		// MongoDB operators in JSON
		`(?i)\{\s*["\']?\$where["\']?\s*:`,
		`(?i)\{\s*["\']?\$ne["\']?\s*:\s*null\s*\}`,
		`(?i)\{\s*["\']?\$gt["\']?\s*:\s*["\']?["\']?\s*\}`,
		`(?i)\{\s*["\']?\$regex["\']?\s*:\s*["\'].*["\']`,
		
		// MongoDB operators in URL params
		`\[\$ne\]=`,
		`\[\$gt\]=`,
		`\[\$regex\]=`,
		`\[\$where\]=`,
		
		// JavaScript in queries
		`(?i)\$where.*function`,
		`(?i)function\s*\(\s*\)\s*\{.*return`,
		
		// MongoDB commands
		`(?i)db\.[a-z]+\.(find|update|remove|drop)`,
	}
	
	compiled := make([]*regexp.Regexp, 0)
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err == nil {
			compiled = append(compiled, re)
		}
	}
	
	return &NoSQLInjectionDetector{patterns: compiled}
}

func (d *NoSQLInjectionDetector) Detect(input string) (bool, string) {
	// Check solo se ha operatori MongoDB
	if !strings.Contains(input, "$") &&
	   !strings.Contains(input, "[$") &&
	   !strings.Contains(input, "function") {
		return false, ""
	}
	
	for _, pattern := range d.patterns {
		if pattern.MatchString(input) {
			return true, "NoSQL Injection attack detected"
		}
	}
	
	return false, ""
}
