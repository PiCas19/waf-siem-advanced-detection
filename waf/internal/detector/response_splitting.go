package detector

import (
	"regexp"
)

type ResponseSplittingDetector struct {
	patterns []*regexp.Regexp
}

func NewResponseSplittingDetector() *ResponseSplittingDetector {
	patterns := []string{
		// CRLF injection con header
		`\r\n[A-Za-z-]+\s*:`,
		`%0d%0a[A-Za-z-]+\s*:`,
		
		// Set-Cookie injection
		`(?i)\r\nSet-Cookie\s*:`,
		`(?i)%0d%0aSet-Cookie\s*:`,
		
		// Location injection
		`(?i)\r\nLocation\s*:`,
		`(?i)%0d%0aLocation\s*:`,
		
		// Double CRLF (response splitting)
		`\r\n\r\n`,
		`%0d%0a%0d%0a`,
		
		// HTTP header injection
		`(?i)\r\nHTTP/1\.[01]`,
	}
	
	compiled := make([]*regexp.Regexp, 0)
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err == nil {
			compiled = append(compiled, re)
		}
	}
	
	return &ResponseSplittingDetector{patterns: compiled}
}

func (d *ResponseSplittingDetector) Detect(input string) (bool, string) {
	for _, pattern := range d.patterns {
		if pattern.MatchString(input) {
			return true, "HTTP Response Splitting attack detected"
		}
	}
	
	return false, ""
}
