package detector

import (
	"regexp"
	"strings"
)

type PathTraversalDetector struct {
	patterns []*regexp.Regexp
}

func NewPathTraversalDetector() *PathTraversalDetector {
	patterns := []string{
		// Multiple traversal
		`\.\./\.\./`,
		`\.\.\\\.\.\\`,
		
		// Encoded
		`%2e%2e/`,
		`%252e%252e/`,
		`%c0%ae%c0%ae/`,
		
		// Absolute paths to sensitive locations
		`^/etc/`,
		`^/proc/`,
		`^c:\\windows`,
		
		// Mixed encodings
		`%2e\./`,
		`\.%2e/`,
	}
	
	compiled := make([]*regexp.Regexp, 0)
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err == nil {
			compiled = append(compiled, re)
		}
	}
	
	return &PathTraversalDetector{patterns: compiled}
}

func (d *PathTraversalDetector) Detect(input string) (bool, string) {
	// Check solo se ha traversal
	if !strings.Contains(input, "..") &&
	   !strings.Contains(input, "%2e") &&
	   !strings.Contains(input, "%252e") {
		return false, ""
	}
	
	// Single ../ might be legitimate
	if strings.Count(input, "../") == 1 && len(input) < 20 {
		return false, ""
	}
	
	for _, pattern := range d.patterns {
		if pattern.MatchString(input) {
			return true, "Path Traversal attack detected"
		}
	}
	
	return false, ""
}
