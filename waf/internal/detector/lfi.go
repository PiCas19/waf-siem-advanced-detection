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
		// Path traversal MULTIPLO
		`\.\./\.\./`,
		`\.\./\.\./\.\./`,
		`\.\.\\\.\.\\`,
		
		// Encoded traversal
		`%2e%2e/`,
		`%2e%2e%2f`,
		`%252e%252e/`,
		`%c0%ae%c0%ae/`,
		
		// File sensibili UNIX
		`/etc/passwd`,
		`/etc/shadow`,
		`/proc/self/environ`,
		`/var/log/.*\.log`,
		
		// File sensibili Windows
		`(?i)c:\\windows\\`,
		`(?i)boot\.ini`,
		`(?i)win\.ini`,
		`(?i)system32\\config`,
		
		// PHP wrappers
		`(?i)php://filter`,
		`(?i)php://input`,
		`(?i)expect://`,
		`(?i)zip://`,
		`(?i)phar://`,
		
		// Null byte
		`\.php%00`,
		`\.txt%00`,
		
		// Config files
		`(?i)\.env$`,
		`(?i)wp-config\.php`,
		`(?i)web\.config`,
		`(?i)\.git/config`,
	}
	
	compiled := make([]*regexp.Regexp, 0)
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err == nil {
			compiled = append(compiled, re)
		}
	}
	
	return &LFIDetector{patterns: compiled}
}

func (d *LFIDetector) Detect(input string) (bool, string) {
	normalized := strings.ToLower(input)
	
	// Check solo se contiene traversal o path
	if !strings.Contains(input, "..") && 
	   !strings.Contains(input, "%2e") &&
	   !strings.Contains(normalized, "/etc/") &&
	   !strings.Contains(normalized, "c:\\") &&
	   !strings.Contains(normalized, "php://") {
		return false, ""
	}
	
	for _, pattern := range d.patterns {
		if pattern.MatchString(normalized) {
			return true, "Local File Inclusion pattern detected"
		}
	}
	
	return false, ""
}
