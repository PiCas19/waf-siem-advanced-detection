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
		// === SHELL COMMAND SEPARATORS (with common commands) ===
		`;\s*(ls|cat|pwd|whoami|id|uname|echo|rm|chmod|wget|curl|nc|bash|sh|python|perl|php|kill|ps|top|netstat|find|grep|awk|sed|tail|head|vi|vim|nano|less|more)`,
		`\|\s*(ls|cat|pwd|whoami|id|uname|echo|rm|chmod|wget|curl|nc|bash|sh|python|perl|php|grep|awk|sed|tail|head|sort|uniq|wc|tee)`,
		`&&\s*(ls|cat|pwd|whoami|id|uname|echo|rm|chmod|wget|curl|nc|bash|sh|python|perl|php|cd|mkdir|touch|cp|mv)`,
		`\|\|\s*(ls|cat|pwd|whoami|id|uname|echo|rm|chmod|wget|curl|nc|bash|sh|exit|true|false)`,

		// === COMMAND SUBSTITUTION ===
		`\$\((cat|ls|whoami|id|pwd|echo|curl|wget|uname|hostname|ifconfig|ip|ps|netstat|env|printenv|date|uptime)`,
		"`" + `(cat|ls|whoami|id|pwd|echo|curl|wget|uname|hostname|ifconfig|ip|ps|netstat|env)`,
		`\$\{[^}]*\}`, // Variable expansion

		// === SHELL INVOCATION ===
		`(?i)\b(bash|sh|zsh|ksh|csh|tcsh|fish)\s+-c`,
		`(?i)\b(bash|sh|cmd|powershell|pwsh)\s+-`,
		`(?i)/bin/(bash|sh|dash|zsh|ksh)`,
		`(?i)/usr/bin/(bash|sh|env|python|perl|ruby|php)`,

		// === NETWORK COMMANDS ===
		`(?i)\b(wget|curl|nc|netcat|telnet|ftp|tftp|scp|ssh|socat)\s+`,
		`(?i)wget\s+http`,
		`(?i)curl\s+http`,
		`(?i)nc\s+-`,
		`(?i)netcat\s+-`,
		`(?i)telnet\s+\d+`,

		// === FILE OPERATIONS ===
		`(?i)\b(chmod|chown|chgrp|chattr)\s+`,
		`(?i)chmod\s+[0-7]{3,4}`,
		`(?i)chmod\s+\+x`,
		`(?i)chown\s+(root|www-data|apache|nginx)`,

		// === DANGEROUS SYSTEM COMMANDS ===
		`(?i)\brm\s+-rf`,
		`(?i)\brm\s+/`,
		`(?i)\bdd\s+if=`,
		`(?i)\bdd\s+of=`,
		`(?i)\bmkfs`,
		`(?i)\bfdisk`,
		`(?i)\bmount\s+`,
		`(?i)\bumount\s+`,
		`(?i)\bkill\s+-9`,
		`(?i)\bkillall\s+`,
		`(?i)\bpkill\s+`,
		`(?i)\bshutdown`,
		`(?i)\breboot`,
		`(?i)\bhalt`,
		`(?i)\bpoweroff`,
		`(?i)\binit\s+`,

		// === FILE REDIRECTION ===
		`>\s*/[a-z/]+`,
		`<\s*/[a-z/]+`,
		`>>\s*/[a-z/]+`,
		`2>\s*/[a-z/]+`,
		`&>\s*/[a-z/]+`,
		`>\s*/etc/`,
		`>\s*/var/`,
		`>\s*/tmp/`,
		`>\s*/dev/`,

		// === ENVIRONMENT VARIABLES ===
		`\$\{[A-Z_]+\}`,
		`\$[A-Z_]{2,}`,
		`\$PATH`,
		`\$HOME`,
		`\$USER`,
		`\$SHELL`,
		`(?i)\$\{IFS\}`, // Internal Field Separator (used for evasion)

		// === PROCESS MANIPULATION ===
		`(?i)\b(ps|top|htop|pgrep|pidof|jobs|fg|bg|nice|nohup)\b`,
		`(?i)\bkill\s+`,
		`(?i)\bkillall\b`,
		`(?i)\bpkill\b`,

		// === FILE READING/WRITING ===
		`(?i)\bcat\s+/etc/`,
		`(?i)\bcat\s+/var/`,
		`(?i)\bhead\s+/etc/`,
		`(?i)\btail\s+/etc/`,
		`(?i)\bless\s+/etc/`,
		`(?i)\bmore\s+/etc/`,
		`(?i)\bnano\s+/etc/`,
		`(?i)\bvi\s+/etc/`,
		`(?i)\bvim\s+/etc/`,

		// === WINDOWS COMMANDS ===
		`(?i)\b(del|erase|format|attrib|copy|xcopy|move|ren|rename)\s+`,
		`(?i)cmd\.exe`,
		`(?i)cmd\s+/c`,
		`(?i)powershell\.exe`,
		`(?i)powershell\s+-`,
		`(?i)pwsh\s+-`,
		`(?i)\bnet\s+(user|localgroup|share|use)`,
		`(?i)\breg\s+(add|delete|query)`,
		`(?i)\bsc\s+(create|delete|start|stop)`,
		`(?i)\btaskkill\s+`,
		`(?i)\btasklist\b`,
		`(?i)\bwmic\b`,
		`(?i)\bcertutil\b`,
		`(?i)\bbitsadmin\b`,

		// === SCRIPTING LANGUAGES ===
		`(?i)\b(python|python2|python3|perl|ruby|php|node|nodejs)\s+-c`,
		`(?i)\b(python|perl|ruby|php|node)\s+.*\.py`,
		`(?i)\b(python|perl|ruby|php|node)\s+.*\.pl`,
		`(?i)\b(python|perl|ruby|php|node)\s+.*\.rb`,
		`(?i)\b(python|perl|ruby|php|node)\s+.*\.php`,
		`(?i)\b(python|perl|ruby|php|node)\s+.*\.js`,

		// === ENCODED CHARACTERS (for evasion) ===
		`%0a`, // Line feed
		`%0d`, // Carriage return
		`%09`, // Tab
		`%00`, // Null byte
		`\n.*?(ls|cat|whoami|id|rm|wget|curl)`,
		`\r.*?(ls|cat|whoami|id|rm|wget|curl)`,

		// === OBFUSCATION TECHNIQUES ===
		`\\x[0-9a-f]{2}`, // Hex encoding
		`\\0[0-7]{2,3}`, // Octal encoding
		`\^\^`, // Windows escape character
		`\$\(.*?\)`, // Command substitution (generic)
		"`" + `.*?` + "`", // Backtick command substitution (generic)

		// === SYSTEM INFORMATION GATHERING ===
		`(?i)\b(whoami|id|groups|hostname|uname|env|printenv|set|export)\b`,
		`(?i)\buname\s+-a`,
		`(?i)\bcat\s+/etc/passwd`,
		`(?i)\bcat\s+/etc/shadow`,
		`(?i)\bcat\s+/etc/hosts`,
		`(?i)\bcat\s+/etc/group`,
		`(?i)\bcat\s+/proc/`,
		`(?i)\bls\s+-la`,
		`(?i)\bfind\s+/`,
		`(?i)\bgrep\s+-r`,

		// === REVERSE SHELLS ===
		`(?i)/dev/(tcp|udp)/`,
		`(?i)bash\s+-i`,
		`(?i)sh\s+-i`,
		`(?i)nc\s+.*\s+-e`,
		`(?i)netcat\s+.*\s+-e`,
		`(?i)mkfifo`,
		`(?i)mknod`,
		`(?i)telnet.*\|`,
		`(?i)bash.*\|.*nc`,
		`(?i)sh.*\|.*nc`,

		// === COMPRESSION/ARCHIVING (potential data exfiltration) ===
		`(?i)\b(tar|zip|gzip|bzip2|compress|7z|rar)\s+`,
		`(?i)tar\s+.*cvf`,
		`(?i)tar\s+.*xvf`,

		// === DATABASE COMMANDS (if accessible via shell) ===
		`(?i)\b(mysql|psql|sqlite3|mongo|redis-cli)\s+`,
		`(?i)mysql\s+-u`,
		`(?i)psql\s+-U`,
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