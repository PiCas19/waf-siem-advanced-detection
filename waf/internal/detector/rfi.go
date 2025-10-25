package detector

import (
	"regexp"
)

// RFIDetector detects Remote File Inclusion attacks
type RFIDetector struct {
	patterns []*regexp.Regexp
}

// NewRFIDetector creates a new RFI detector
func NewRFIDetector() *RFIDetector {
	patterns := []string{
		// === HTTP/HTTPS PROTOCOLS ===
		`(?i)(https?://)`,
		`(?i)http://`,
		`(?i)https://`,
		`(?i)ftp://`,
		`(?i)ftps://`,
		`(?i)sftp://`,
		`(?i)tftp://`,

		// === URL-ENCODED PROTOCOLS ===
		`(?i)%68%74%74%70`, // http
		`(?i)%66%74%70`,    // ftp
		`(?i)%68%74%74%70%73`, // https
		`(?i)%66%69%6c%65`, // file
		`(?i)%64%61%74%61`, // data

		// === DOUBLE-ENCODED PROTOCOLS ===
		`(?i)%2568%2574%2574%2570`, // http double-encoded
		`(?i)%2566%2574%2570`, // ftp double-encoded

		// === PHP STREAM WRAPPERS ===
		`(?i)php://`,
		`(?i)php://filter`,
		`(?i)php://input`,
		`(?i)php://output`,
		`(?i)php://stdin`,
		`(?i)php://stdout`,
		`(?i)php://stderr`,
		`(?i)php://fd`,
		`(?i)php://memory`,
		`(?i)php://temp`,

		// === FILE PROTOCOL ===
		`(?i)file://`,
		`(?i)file:///`,
		`(?i)file://localhost/`,

		// === DATA URI ===
		`(?i)data://`,
		`(?i)data:text/`,
		`(?i)data:application/`,
		`(?i)data:image/`,

		// === OTHER WRAPPERS ===
		`(?i)expect://`,
		`(?i)zip://`,
		`(?i)zlib://`,
		`(?i)glob://`,
		`(?i)phar://`,
		`(?i)rar://`,
		`(?i)ogg://`,
		`(?i)ssh2://`,
		`(?i)compress.zlib://`,
		`(?i)compress.bzip2://`,

		// === SMB/UNC PATHS (Windows) ===
		`(?i)\\\\[a-z0-9]`,
		`(?i)\\\\[0-9]{1,3}\.[0-9]{1,3}`,
		`(?i)smb://`,

		// === REMOTE INCLUDES WITH PARAMETERS ===
		`\?.*?=.*?https?://`,
		`\?.*?=.*?ftp://`,
		`\?.*?=.*?file://`,
		`\?.*?=.*?php://`,
		`&.*?=.*?https?://`,
		`&.*?=.*?ftp://`,

		// === REMOTE FILE INCLUSION IN PARAMETERS ===
		`(?i)(page|file|document|folder|root|path|pg|style|pdf|template|php_path|doc)=.*?https?://`,
		`(?i)(page|file|document|folder|root|path|pg|style|pdf|template|php_path|doc)=.*?ftp://`,
		`(?i)(page|file|document|folder|root|path|pg|style|pdf|template|php_path|doc)=.*?php://`,

		// === URL WITH SCRIPT EXTENSIONS ===
		`https?://.*?\.(php|asp|aspx|jsp|cgi|pl|py|rb|sh)`,
		`ftp://.*?\.(php|asp|aspx|jsp|cgi|pl|py|rb|sh)`,

		// === LOCALHOST/INTERNAL IPS (SSRF) ===
		`(?i)https?://localhost`,
		`(?i)https?://127\.0\.0\.1`,
		`(?i)https?://0\.0\.0\.0`,
		`(?i)https?://10\.`,
		`(?i)https?://172\.(1[6-9]|2[0-9]|3[0-1])\.`,
		`(?i)https?://192\.168\.`,
		`(?i)https?://169\.254\.`, // Link-local
		`(?i)https?://\[::1\]`, // IPv6 localhost
		`(?i)https?://\[::ffff:127\.0\.0\.1\]`, // IPv6-mapped IPv4

		// === OBFUSCATED IPS ===
		`(?i)https?://0x[0-9a-f]+`, // Hex IP
		`(?i)https?://[0-9]{8,10}`, // Decimal IP
		`(?i)https?://0[0-7]+`, // Octal IP

		// === EXTERNAL RESOURCE LOADING ===
		`(?i)<script.*?src=.*?https?://`,
		`(?i)<link.*?href=.*?https?://`,
		`(?i)<img.*?src=.*?https?://`,
		`(?i)<iframe.*?src=.*?https?://`,
		`(?i)@import.*?https?://`,

		// === WEBHOOK/CALLBACK URLs (potential exfiltration) ===
		`(?i)callback=.*?https?://`,
		`(?i)webhook=.*?https?://`,
		`(?i)redirect=.*?https?://`,
		`(?i)url=.*?https?://`,
		`(?i)link=.*?https?://`,
		`(?i)uri=.*?https?://`,
		`(?i)dest=.*?https?://`,
		`(?i)destination=.*?https?://`,
		`(?i)next=.*?https?://`,
		`(?i)goto=.*?https?://`,
		`(?i)target=.*?https?://`,

		// === SUSPICIOUS DOMAINS (common in attacks) ===
		`(?i)https?://.*?\.(tk|ml|ga|cf|gq)`, // Free TLDs
		`(?i)https?://.*?\.ngrok\.io`,
		`(?i)https?://.*?\.localtunnel\.me`,
		`(?i)https?://.*?\.burpcollaborator\.net`,
		`(?i)https?://.*?\.requestbin\.`,
		`(?i)https?://.*?\.webhook\.site`,
		`(?i)https?://.*?\.pipedream\.net`,

		// === CLOUD METADATA SERVICES (SSRF) ===
		`(?i)https?://169\.254\.169\.254`, // AWS/GCP/Azure metadata
		`(?i)https?://metadata\.google\.internal`,
		`(?i)https?://metadata\.azure\.com`,
		`(?i)http://instance-data`,

		// === JAR PROTOCOL (Java) ===
		`(?i)jar:https?://`,
		`(?i)jar:file://`,

		// === GOPHER PROTOCOL (SSRF) ===
		`(?i)gopher://`,
		`(?i)dict://`,
		`(?i)ldap://`,
		`(?i)ldaps://`,

		// === URL WITH SPECIAL CHARACTERS (evasion) ===
		`https?://.*?@`, // URL with credentials
		`https?://.*?%00`, // Null byte in URL
		`https?://.*?\.\./`, // Path traversal in URL
	}
	
	compiled := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		compiled[i] = regexp.MustCompile(p)
	}
	
	return &RFIDetector{patterns: compiled}
}

// Detect checks if input contains RFI patterns
func (d *RFIDetector) Detect(input string) (bool, string) {
	for _, pattern := range d.patterns {
		if pattern.MatchString(input) {
			return true, "Remote File Inclusion pattern detected: " + pattern.String()
		}
	}
	
	return false, ""
}