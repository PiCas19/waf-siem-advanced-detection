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
		// DOCTYPE con ENTITY
		`(?i)<!DOCTYPE[^>]*\[.*<!ENTITY`,
		`(?i)<!ENTITY[^>]*SYSTEM`,
		`(?i)<!ENTITY[^>]*PUBLIC`,
		
		// SYSTEM con file
		`(?i)SYSTEM\s+["']file://`,
		`(?i)SYSTEM\s+["']http://`,
		
		// XInclude
		`(?i)<xi:include`,
		`(?i)xmlns:xi.*XInclude`,
		
		// Parameter entities
		`(?i)<!ENTITY\s+%`,
		`(?i)%[a-zA-Z]+;.*SYSTEM`,
	}
	
	compiled := make([]*regexp.Regexp, 0)
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err == nil {
			compiled = append(compiled, re)
		}
	}
	
	return &XXEDetector{patterns: compiled}
}

func (d *XXEDetector) Detect(input string) (bool, string) {
	// Check solo se è XML
	if !strings.Contains(input, "<!") &&
	   !strings.Contains(input, "<?xml") {
		return false, ""
	}
	
	for _, pattern := range d.patterns {
		if pattern.MatchString(input) {
			return true, "XML External Entity attack detected"
		}
	}
	
	return false, ""
}
