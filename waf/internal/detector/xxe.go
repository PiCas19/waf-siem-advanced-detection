package detector

import (
	"regexp"
	"strings"
)

type XXEDetector struct {
	patterns []*regexp.Regexp
}

func NewXXEDetector() *XXEDetector {
	patterns := []string{
		`(?i)<!ENTITY`,
		`(?i)<!DOCTYPE.*ENTITY`,
		`(?i)SYSTEM\s+["']file://`,
		`(?i)SYSTEM\s+["']http://`,
		`(?i)PUBLIC\s+["']`,
		`(?i)<!ENTITY\s+%`,
		`(?i)<xi:include`,
		`(?i)file:///etc/`,
		`(?i)file:///var/`,
	}
	
	compiled := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		compiled[i] = regexp.MustCompile(p)
	}
	
	return &XXEDetector{patterns: compiled}
}

func (d *XXEDetector) Detect(input string) (bool, string) {
	if !strings.Contains(input, "<") {
		return false, ""
	}
	
	for _, pattern := range d.patterns {
		if pattern.MatchString(input) {
			return true, "XML External Entity attack detected"
		}
	}
	
	return false, ""
}