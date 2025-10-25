package detector

import (
	"regexp"
	"strings"
)

type PrototypePollutionDetector struct {
	patterns []*regexp.Regexp
}

func NewPrototypePollutionDetector() *PrototypePollutionDetector {
	patterns := []string{
		// __proto__ access
		`(?i)__proto__\[`,
		`(?i)__proto__\.`,
		`(?i)\["__proto__"\]`,
		`(?i)\['__proto__'\]`,
		
		// constructor.prototype
		`(?i)constructor\[["']prototype["']\]`,
		`(?i)constructor\.prototype\.`,
		
		// In JSON
		`(?i)\{\s*["']__proto__["']\s*:`,
		`(?i)\{\s*["']constructor["']\s*:.*["']prototype["']`,
	}
	
	compiled := make([]*regexp.Regexp, 0)
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err == nil {
			compiled = append(compiled, re)
		}
	}
	
	return &PrototypePollutionDetector{patterns: compiled}
}

func (d *PrototypePollutionDetector) Detect(input string) (bool, string) {
	inputLower := strings.ToLower(input)
	
	// Check solo se ha indicatori
	if !strings.Contains(inputLower, "proto") &&
	   !strings.Contains(inputLower, "constructor") {
		return false, ""
	}
	
	for _, pattern := range d.patterns {
		if pattern.MatchString(input) {
			return true, "Prototype Pollution attack detected"
		}
	}
	
	return false, ""
}
