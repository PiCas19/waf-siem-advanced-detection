package detector

import (
	"regexp"
	"strings"
)

type LDAPInjectionDetector struct {
	patterns []*regexp.Regexp
}

func NewLDAPInjectionDetector() *LDAPInjectionDetector {
	patterns := []string{
		// LDAP filter injection
		`\*\)\(.*=`,
		`\)\(\|`,
		`\)\(&`,
		`\(\|\(.*=\*`,
		`\(&\(.*=\*`,
		
		// Wildcard bypass
		`\(cn=\*\)`,
		`\(uid=\*\)`,
		`\(objectClass=\*\)`,
		
		// Boolean operators
		`\*\)\(\|`,
		`\*\)\(&`,
	}
	
	compiled := make([]*regexp.Regexp, 0)
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err == nil {
			compiled = append(compiled, re)
		}
	}
	
	return &LDAPInjectionDetector{patterns: compiled}
}

func (d *LDAPInjectionDetector) Detect(input string) (bool, string) {
	// Check solo se ha sintassi LDAP
	if !strings.Contains(input, "(") ||
	   !strings.Contains(input, ")") {
		return false, ""
	}
	
	// Count parenthesis - if unbalanced, likely injection
	openCount := strings.Count(input, "(")
	closeCount := strings.Count(input, ")")
	if openCount > 0 && openCount != closeCount {
		// Could be injection
	}
	
	for _, pattern := range d.patterns {
		if pattern.MatchString(input) {
			return true, "LDAP Injection attack detected"
		}
	}
	
	return false, ""
}
