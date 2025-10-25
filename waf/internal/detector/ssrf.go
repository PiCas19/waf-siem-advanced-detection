package detector

import (
	"regexp"
	"strings"
)

type SSRFDetector struct {
	patterns []*regexp.Regexp
}

func NewSSRFDetector() *SSRFDetector {
	patterns := []string{
		// Localhost in parametri URL
		`(?i)(url|uri|redirect|target|callback|webhook|dest|goto|link)=.*?https?://(localhost|127\.0\.0\.1)`,
		
		// Private IPs in parametri
		`(?i)(url|uri|redirect)=.*?https?://10\.`,
		`(?i)(url|uri|redirect)=.*?https?://192\.168\.`,
		`(?i)(url|uri|redirect)=.*?https?://172\.(1[6-9]|2[0-9]|3[0-1])\.`,
		
		// Cloud metadata
		`169\.254\.169\.254`,
		`(?i)metadata\.google\.internal`,
		`(?i)metadata\.azure\.com`,
		
		// Special protocols
		`(?i)(url|uri)=.*?file:///`,
		`(?i)(url|uri)=.*?dict://`,
		`(?i)(url|uri)=.*?gopher://`,
		
		// @ bypass
		`(?i)https?://.*@(localhost|127\.0\.0\.1|10\.|192\.168\.)`,
	}
	
	compiled := make([]*regexp.Regexp, 0)
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err == nil {
			compiled = append(compiled, re)
		}
	}
	
	return &SSRFDetector{patterns: compiled}
}

func (d *SSRFDetector) Detect(input string) (bool, string) {
	inputLower := strings.ToLower(input)
	
	// Check solo se ha indicatori
	if !strings.Contains(inputLower, "localhost") &&
	   !strings.Contains(input, "127.0.0.1") &&
	   !strings.Contains(input, "169.254") &&
	   !strings.Contains(input, "192.168") &&
	   !strings.Contains(inputLower, "metadata") {
		return false, ""
	}
	
	for _, pattern := range d.patterns {
		if pattern.MatchString(input) {
			return true, "Server-Side Request Forgery attack detected"
		}
	}
	
	return false, ""
}
