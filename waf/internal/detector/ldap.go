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
		`\*\)\(`,
		`\)\(`,
		`\*\|`,
		`\|\(`,
		`\(\*\)`,
		`\(\|`,
		`\(&`,
		`\(!`,
		`(?i)\(cn=\*\)`,
		`(?i)\(uid=\*\)`,
	}
	
	compiled := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		compiled[i] = regexp.MustCompile(p)
	}
	
	return &LDAPInjectionDetector{patterns: compiled}
}

func (d *LDAPInjectionDetector) Detect(input string) (bool, string) {
	if !strings.Contains(input, "(") && !strings.Contains(input, "*") {
		return false, ""
	}
	
	for _, pattern := range d.patterns {
		if pattern.MatchString(input) {
			return true, "LDAP Injection attack detected"
		}
	}
	
	return false, ""
}