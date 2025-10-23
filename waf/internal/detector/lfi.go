package detector

import (
	"regexp"
	"strings"
)

// LFIDetector detects Local File Inclusion attacks
type LFIDetector struct {
	patterns []*regexp.Regexp
}

// NewLFIDetector creates a new LFI detector
func NewLFIDetector() *LFIDetector {
	patterns := []string{
		// Path traversal
		`\.\./`,
		`\.\.\\`,
		`\.\./\.\./`,
		
		// URL-encoded traversal
		`%2e%2e/`,
		`%2e%2e\\`,
		`%252e%252e/`,
		
		// Double-encoded
		`%%32%65%%32%65/`,
		
		// Unix sensitive files
		`/etc/passwd`,
		`/etc/shadow`,
		`/etc/hosts`,
		`/etc/group`,
		`/proc/self/environ`,
		`/proc/version`,
		`/var/log/`,
		`/var/www/`,
		
		// Windows sensitive files
		`c:\\windows`,
		`c:\\winnt`,
		`boot\.ini`,
		`win\.ini`,
		`system32`,
		
		// PHP wrappers
		`php://filter`,
		`php://input`,
		
		// Null byte injection
		`%00`,
		`\x00`,
	}
	
	compiled := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		compiled[i] = regexp.MustCompile(`(?i)` + p)
	}
	
	return &LFIDetector{patterns: compiled}
}

// Detect checks if input contains LFI patterns
func (d *LFIDetector) Detect(input string) (bool, string) {
	normalized := strings.ToLower(input)
	
	for _, pattern := range d.patterns {
		if pattern.MatchString(normalized) {
			return true, "Local File Inclusion pattern detected: " + pattern.String()
		}
	}
	
	return false, ""
}