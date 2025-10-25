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
		`__proto__`,
		`constructor\.prototype`,
		`\.prototype\.`,
		`\["prototype"\]`,
		`\['prototype'\]`,
		`\["__proto__"\]`,
		`\['__proto__'\]`,
	}
	
	compiled := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		compiled[i] = regexp.MustCompile(`(?i)` + p)
	}
	
	return &PrototypePollutionDetector{patterns: compiled}
}

func (d *PrototypePollutionDetector) Detect(input string) (bool, string) {
	inputLower := strings.ToLower(input)
	if !strings.Contains(inputLower, "proto") && !strings.Contains(inputLower, "constructor") {
		return false, ""
	}
	
	for _, pattern := range d.patterns {
		if pattern.MatchString(input) {
			return true, "Prototype Pollution attack detected"
		}
	}
	
	return false, ""
}