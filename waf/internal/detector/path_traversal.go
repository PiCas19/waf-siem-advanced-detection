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
		`\.\./`,
		`\.\.\\`,
		`%2e%2e/`,
		`%252e%252e/`,
		`%c0%ae%c0%ae/`,
		`\\\\`,
		`//`,
		`%00`,
	}
	
	compiled := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		compiled[i] = regexp.MustCompile(p)
	}
	
	return &PathTraversalDetector{patterns: compiled}
}

func (d *PathTraversalDetector) Detect(input string) (bool, string) {
	if !strings.Contains(input, "..") && !strings.Contains(input, "%2e") && !strings.Contains(input, "\\") {
		return false, ""
	}
	
	for _, pattern := range d.patterns {
		if pattern.MatchString(input) {
			return true, "Path Traversal attack detected"
		}
	}
	
	return false, ""
}