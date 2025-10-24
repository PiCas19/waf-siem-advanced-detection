package detector

import (
	"regexp"
	"strings"
)

// CommandInjectionDetector detects command injection attacks
type CommandInjectionDetector struct {
	patterns []*regexp.Regexp
}

// NewCommandInjectionDetector creates a new command injection detector
func NewCommandInjectionDetector() *CommandInjectionDetector {
	patterns := []string{
		// Shell metacharacters
		`[;|&$><` + "`" + `]`,
		
		// Command substitution
		`\$\(.*?\)`,
		"`" + `.*?` + "`",
		
		// Shell commands
		`(?i)\b(bash|sh|cmd|powershell|pwsh)\b`,
		`(?i)\b(wget|curl|nc|netcat|telnet)\b`,
		`(?i)\b(chmod|chown|chgrp|kill|killall)\b`,
		`(?i)\b(cat|more|less|head|tail)\b`,
		
		// Dangerous commands
		`(?i)rm\s+-rf`,
		`(?i)dd\s+if=`,
		`(?i)mkfs`,
		
		// Pipe and redirection
		`\|\s*\w+`,
		`>\s*/`,
		`<\s*/`,
		
		// Environment variables
		`\$\{.*?\}`,
		`\$[A-Z_]+`,
		
		// Windows commands
		`(?i)\b(del|erase|format|attrib)\b`,
		`(?i)cmd\.exe`,
		`(?i)powershell\.exe`,
		
		// Encoded commands
		`%0a`,  // Line feed
		`%0d`,  // Carriage return
		`%09`,  // Tab
	}
	
	compiled := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		compiled[i] = regexp.MustCompile(p)
	}
	
	return &CommandInjectionDetector{patterns: compiled}
}

// Detect checks if input contains command injection patterns
func (d *CommandInjectionDetector) Detect(input string) (bool, string) {
	// Check both original and lowercase
	inputs := []string{input, strings.ToLower(input)}
	
	for _, inp := range inputs {
		for _, pattern := range d.patterns {
			if pattern.MatchString(inp) {
				return true, "Command injection pattern detected: " + pattern.String()
			}
		}
	}
	
	return false, ""
}