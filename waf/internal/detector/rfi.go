package detector

import (
	"regexp"
	"strings"
)

type RFIDetector struct {
	patterns []*regexp.Regexp
}

func NewRFIDetector() *RFIDetector {
	patterns := []string{
		// URL in parametri sospetti
		`(?i)(page|file|document|folder|path|template|include|doc|load|view|content)=.*?https?://`,
		`(?i)\?(.*&)?(url|path|file|src)=https?://`,
		
		// PHP wrappers
		`(?i)php://filter`,
		`(?i)php://input`,
		`(?i)expect://`,
		`(?i)data://text/`,
		
		// File protocol
		`(?i)file:///`,
		
		// UNC paths
		`\\\\[a-z0-9][\w.-]+\\`,
		`(?i)smb://`,
		
		// Encoded protocols
		`%68%74%74%70://`, // http://
		`%66%74%70://`,    // ftp://
	}
	
	compiled := make([]*regexp.Regexp, 0)
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err == nil {
			compiled = append(compiled, re)
		}
	}
	
	return &RFIDetector{patterns: compiled}
}

func (d *RFIDetector) Detect(input string) (bool, string) {
	inputLower := strings.ToLower(input)
	
	// Ignora URL normali senza parametri sospetti
	if (strings.HasPrefix(inputLower, "http://") || strings.HasPrefix(inputLower, "https://")) &&
	   !strings.Contains(input, "=http") &&
	   !strings.Contains(input, "=https") {
		return false, ""
	}
	
	// Check solo se ha indicatori
	if !strings.Contains(inputLower, "http") &&
	   !strings.Contains(inputLower, "php://") &&
	   !strings.Contains(inputLower, "file://") &&
	   !strings.Contains(input, "\\\\") {
		return false, ""
	}
	
	for _, pattern := range d.patterns {
		if pattern.MatchString(input) {
			return true, "Remote File Inclusion pattern detected"
		}
	}
	
	return false, ""
}
