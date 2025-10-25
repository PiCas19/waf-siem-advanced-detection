package detector

import (
	"regexp"
)

type SSRFDetector struct {
	patterns []*regexp.Regexp
}

func NewSSRFDetector() *SSRFDetector {
	patterns := []string{
		`(?i)https?://localhost`,
		`(?i)https?://127\.0\.0\.1`,
		`(?i)https?://0\.0\.0\.0`,
		`(?i)https?://10\.`,
		`(?i)https?://172\.(1[6-9]|2[0-9]|3[0-1])\.`,
		`(?i)https?://192\.168\.`,
		`(?i)169\.254\.169\.254`,
		`(?i)metadata\.google\.internal`,
		`(?i)metadata\.azure\.com`,
		`(?i)file:///`,
		`(?i)dict://`,
		`(?i)gopher://`,
	}
	
	compiled := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		compiled[i] = regexp.MustCompile(p)
	}
	
	return &SSRFDetector{patterns: compiled}
}

func (d *SSRFDetector) Detect(input string) (bool, string) {
	for _, pattern := range d.patterns {
		if pattern.MatchString(input) {
			return true, "Server-Side Request Forgery attack detected"
		}
	}
	
	return false, ""
}