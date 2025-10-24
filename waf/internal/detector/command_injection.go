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
		// Shell command separators (SOLO se seguiti da comandi)
		`;\s*(ls|cat|pwd|whoami|id|uname|echo|rm|chmod|wget|curl|nc|bash|sh|python|perl|php|kill|ps|top|netstat)`,
		`\|\s*(ls|cat|pwd|whoami|id|uname|echo|rm|chmod|wget|curl|nc|bash|sh|python|perl|php|grep|awk|sed)`,
		`&&\s*(ls|cat|pwd|whoami|id|uname|echo|rm|chmod|wget|curl|nc|bash|sh)`,
		`\|\|\s*(ls|cat|pwd|whoami|id|uname|echo|rm|chmod|wget|curl|nc|bash|sh)`,
		
		// Command substitution con comandi specifici
		`\$\((cat|ls|whoami|id|pwd|echo|curl|wget|uname|hostname|ifconfig|ip)`,
		"`" + `(cat|ls|whoami|id|pwd|echo|curl|wget|uname|hostname)`,
		
		// Shell commands con flags
		`(?i)\b(bash|sh|cmd|powershell|pwsh)\s+-`,
		`(?i)\b(wget|curl|nc|netcat|telnet)\s+`,
		`(?i)\b(chmod|chown|chgrp|kill|killall)\s+`,
		
		// Dangerous commands specifici
		`(?i)rm\s+-rf`,
		`(?i)dd\s+if=`,
		`(?i)mkfs`,
		
		// File redirection con path
		`>\s*/[a-z/]+`,
		`<\s*/[a-z/]+`,
		`>>\s*/[a-z/]+`,
		
		// Environment variables (non in contesto HTML)
		`\$\{[A-Z_]+\}`,
		`\$[A-Z_]{2,}`,
		
		// Windows commands
		`(?i)\b(del|erase|format|attrib)\s+`,
		`(?i)cmd\.exe`,
		`(?i)powershell\.exe`,
		
		// Encoded line breaks (usati per command injection)
		`%0a`,
		`%0d`,
		`\n.*?(ls|cat|whoami|id|rm)`,
	}
	
	compiled := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		compiled[i] = regexp.MustCompile(p)
	}
	
	return &CommandInjectionDetector{patterns: compiled}
}

// Detect checks if input contains command injection patterns
func (d *CommandInjectionDetector) Detect(input string) (bool, string) {
	inputLower := strings.ToLower(input)
	
	// ❌ IGNORA se contiene chiari tag HTML (è XSS!)
	htmlIndicators := []string{
		"<script", "</script", "<img", "</img", "<iframe", "</iframe",
		"<svg", "<object", "<embed", "<body", "<div", "<span",
		"onerror=", "onload=", "onclick=", "onmouseover=",
		"javascript:", "alert(", "prompt(", "confirm(",
	}
	
	for _, indicator := range htmlIndicators {
		if strings.Contains(inputLower, indicator) {
			return false, "" // È XSS, non Command Injection
		}
	}
	
	// ❌ IGNORA se contiene chiari pattern SQL
	sqlIndicators := []string{
		"union select", "union all select", 
		"or 1=1", "or '1'='1", "' or '", "\" or \"",
		"drop table", "insert into", "delete from",
	}
	
	for _, indicator := range sqlIndicators {
		if strings.Contains(inputLower, indicator) {
			return false, "" // È SQL Injection, non Command Injection
		}
	}
	
	// ❌ IGNORA se contiene path traversal senza comandi
	if strings.Contains(input, "../") && !containsCommand(inputLower) {
		return false, "" // È LFI, non Command Injection
	}
	
	// ✅ Ora controlla i pattern di Command Injection
	for _, pattern := range d.patterns {
		if pattern.MatchString(input) || pattern.MatchString(inputLower) {
			return true, "Command injection pattern detected"
		}
	}
	
	return false, ""
}

// containsCommand verifica se l'input contiene comandi shell comuni
func containsCommand(input string) bool {
	commands := []string{
		"ls", "cat", "pwd", "whoami", "id", "uname", "echo",
		"rm", "chmod", "wget", "curl", "nc", "bash", "sh",
		"python", "perl", "php", "grep", "awk", "sed",
	}
	
	for _, cmd := range commands {
		if strings.Contains(input, cmd) {
			return true
		}
	}
	
	return false
}