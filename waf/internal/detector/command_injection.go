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
		// Separatori + comandi comuni
		`;\s*(ls|cat|pwd|whoami|id|uname|rm|chmod|wget|curl|nc|bash|sh|python|perl|php)\b`,
		`\|\s*(ls|cat|pwd|whoami|id|uname|grep|awk|sed|tail|head|bash|sh)\b`,
		`&&\s*(ls|cat|pwd|whoami|id|uname|rm|chmod|bash|sh)\b`,
		
		// Command substitution
		`\$\((ls|cat|whoami|id|pwd|uname|hostname|ifconfig|ps|netstat)\b`,
		"`" + `(ls|cat|whoami|id|pwd|uname|hostname|ps)\b`,
		
		// Comandi pericolosi con flag
		`(?i)\b(bash|sh|cmd|powershell)\s+-[ce]`,
		`(?i)\b(wget|curl)\s+https?://`,
		`(?i)\b(nc|netcat)\s+-[le]`,
		
		// Comandi distruttivi
		`(?i)\brm\s+-rf\s+/`,
		`(?i)\bdd\s+if=`,
		
		// Redirection verso file di sistema
		`>\s*/etc/`,
		`>\s*/var/`,
		`>\s*/tmp/.*\.sh`,
		
		// Encoded newlines
		`%0a(ls|cat|whoami|id|rm)`,
		`%0d(ls|cat|whoami|id|rm)`,
	}
	
	compiled := make([]*regexp.Regexp, 0)
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err == nil {
			compiled = append(compiled, re)
		}
	}
	
	return &CommandInjectionDetector{patterns: compiled}
}

func (d *CommandInjectionDetector) Detect(input string) (bool, string) {
	inputLower := strings.ToLower(input)
	
	// Ignora HTML
	htmlIndicators := []string{"<script", "</script", "<img", "onerror=", "javascript:"}
	for _, indicator := range htmlIndicators {
		if strings.Contains(inputLower, indicator) {
			return false, ""
		}
	}
	
	// Ignora SQL
	sqlIndicators := []string{"union select", "or 1=1", "drop table"}
	for _, indicator := range sqlIndicators {
		if strings.Contains(inputLower, indicator) {
			return false, ""
		}
	}
	
	// Check solo se ha indicatori
	if !strings.Contains(input, ";") &&
	   !strings.Contains(input, "|") &&
	   !strings.Contains(input, "&&") &&
	   !strings.Contains(input, "$(") &&
	   !strings.Contains(input, "`") &&
	   !strings.Contains(input, "%0a") {
		return false, ""
	}
	
	for _, pattern := range d.patterns {
		if pattern.MatchString(input) || pattern.MatchString(inputLower) {
			return true, "Command injection pattern detected"
		}
	}
	
	return false, ""
}
