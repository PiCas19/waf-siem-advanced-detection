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
		`(?i)\$where`,
		`(?i)\$ne`,
		`(?i)\$gt`,
		`(?i)\$lt`,
		`(?i)\$in`,
		`(?i)\$or`,
		`(?i)\$and`,
		`(?i)\$regex`,
		`(?i)\$set`,
		`(?i)function\s*\(`,
		`(?i)db\.`,
	}
	
	compiled := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		compiled[i] = regexp.MustCompile(p)
	}
	
	return &NoSQLInjectionDetector{patterns: compiled}
}

func (d *NoSQLInjectionDetector) Detect(input string) (bool, string) {
	if !strings.Contains(input, "$") && !strings.Contains(input, "{") {
		return false, ""
	}
	
	for _, pattern := range d.patterns {
		if pattern.MatchString(input) {
			return true, "NoSQL Injection attack detected"
		}
	}
	
	return false, ""
}