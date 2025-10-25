package detector

import (
	"regexp"
)

type ResponseSplittingDetector struct {
	patterns []*regexp.Regexp
}

func NewResponseSplittingDetector() *ResponseSplittingDetector {
	patterns := []string{
		`\r\n`,
		`%0d%0a`,
		`%0D%0A`,
		`(?i)\r\nSet-Cookie:`,
		`(?i)%0d%0aSet-Cookie:`,
		`(?i)\r\nLocation:`,
		`\r\n\r\n`,
		`%0d%0a%0d%0a`,
	}
	
	compiled := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		compiled[i] = regexp.MustCompile(p)
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