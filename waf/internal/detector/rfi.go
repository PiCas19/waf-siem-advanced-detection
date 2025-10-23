package detector

import (
	"regexp"
)

// RFIDetector detects Remote File Inclusion attacks
type RFIDetector struct {
	patterns []*regexp.Regexp
}

// NewRFIDetector creates a new RFI detector
func NewRFIDetector() *RFIDetector {
	patterns := []string{
		// HTTP/HTTPS protocols
		`(?i)(https?://)`,
		`(?i)ftp://`,
		
		// URL-encoded protocols
		`(?i)%68%74%74%70`,  // http
		`(?i)%66%74%70`,     // ftp
		
		// PHP stream wrappers
		`(?i)php://`,
		`(?i)file://`,
		`(?i)data://`,
		`(?i)expect://`,
		`(?i)zip://`,
		`(?i)zlib://`,
		`(?i)glob://`,
		
		// Phar wrapper
		`(?i)phar://`,
		
		// SMB shares (Windows)
		`(?i)\\\\`,
		
		// Remote includes with parameters
		`\?.*?=.*?https?://`,
	}
	
	compiled := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		compiled[i] = regexp.MustCompile(p)
	}
	
	return &RFIDetector{patterns: compiled}
}

// Detect checks if input contains RFI patterns
func (d *RFIDetector) Detect(input string) (bool, string) {
	for _, pattern := range d.patterns {
		if pattern.MatchString(input) {
			return true, "Remote File Inclusion pattern detected: " + pattern.String()
		}
	}
	
	return false, ""
}