package detector

import (
	"regexp"
	"strings"
)

type CommandInjectionDetector struct {
	patterns []*regexp.Regexp
}

func NewCommandInjectionDetector() *CommandInjectionDetector {
	patterns := []string{
		`;\s*(ls|cat|pwd|whoami|id|uname|echo|rm|chmod|wget|curl|nc|bash|sh|python|perl|php|kill|ps|grep)`,
		`\|\s*(ls|cat|pwd|whoami|id|uname|echo|rm|chmod|wget|curl|nc|bash|sh|grep|awk|sed)`,
		`&&\s*(ls|cat|pwd|whoami|id|uname|echo|rm|chmod|wget|curl|nc|bash|sh)`,
		`\|\|\s*(ls|cat|pwd|whoami|id|uname|echo|rm)`,
		`\$\((cat|ls|whoami|id|pwd|echo|curl|wget|uname|hostname)`,
		"`" + `(cat|ls|whoami|id|pwd|echo|curl|wget)`,
		`(?i)\b(bash|sh|cmd|powershell|pwsh)\s+-`,
		`(?i)\b(wget|curl|nc|netcat|telnet)\s+`,
		`(?i)\b(chmod|chown|kill)\s+`,
		`(?i)rm\s+-rf`,
		`(?i)dd\s+if=`,
		`(?i)mkfs`,
		`>\s*/[a-z/]+`,
		`<\s*/[a-z/]+`,
		`\$\{[A-Z_]+\}`,
		`(?i)\b(del|erase|format)\s+`,
		`(?i)cmd\.exe`,
		`(?i)powershell\.exe`,
		`%0a`,
		`%0d`,
	}
	
	compiled := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		compiled[i] = regexp.MustCompile(p)
	}
	
	return &CommandInjectionDetector{patterns: compiled}
}

func (d *CommandInjectionDetector) Detect(input string) (bool, string) {
	inputLower := strings.ToLower(input)
	
	htmlIndicators := []string{"<script", "</script", "<img", "onerror=", "onload=", "javascript:", "alert("}
	for _, indicator := range htmlIndicators {
		if strings.Contains(inputLower, indicator) {
			return false, ""
		}
	}
	
	sqlIndicators := []string{"union select", "or 1=1", "or '1'='1", "drop table"}
	for _, indicator := range sqlIndicators {
		if strings.Contains(inputLower, indicator) {
			return false, ""
		}
	}
	
	for _, pattern := range d.patterns {
		if pattern.MatchString(input) || pattern.MatchString(inputLower) {
			return true, "Command injection pattern detected"
		}
	}
	
	return false, ""
}