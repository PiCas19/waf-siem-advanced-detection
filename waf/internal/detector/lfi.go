package detector

import (
	"regexp"
	"strings"
)

type LFIDetector struct {
	patterns []*regexp.Regexp
}

func NewLFIDetector() *LFIDetector {
	patterns := []string{
		`\.\./`,
		`\.\.\\`,
		`%2e%2e/`,
		`%2e%2e\\`,
		`%252e%252e/`,
		`/etc/passwd`,
		`/etc/shadow`,
		`/etc/hosts`,
		`/proc/self/environ`,
		`/var/log/`,
		`(?i)c:\\windows`,
		`(?i)boot\.ini`,
		`(?i)win\.ini`,
		`(?i)php://filter`,
		`(?i)php://input`,
		`(?i)expect://`,
		`(?i)data://`,
		`%00`,
		`(?i)\.env`,
		`(?i)\.git/`,
		`(?i)wp-config\.php`,
	}
	
	compiled := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		compiled[i] = regexp.MustCompile(p)
	}
	
	return &LFIDetector{patterns: compiled}
}

func (d *LFIDetector) Detect(input string) (bool, string) {
	normalized := strings.ToLower(input)
	
	for _, pattern := range d.patterns {
		if pattern.MatchString(normalized) {
			return true, "Local File Inclusion pattern detected"
		}
	}
	
	return false, ""
}