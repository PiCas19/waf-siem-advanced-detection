package detector

import (
	"regexp"
	"strings"
)

// LFIDetector detects Local File Inclusion attacks
type LFIDetector struct {
	patterns []*regexp.Regexp
}

// NewLFIDetector creates a new LFI detector
func NewLFIDetector() *LFIDetector {
	patterns := []string{
		// === PATH TRAVERSAL (BASIC) ===
		`\.\./`,
		`\.\.\\`,
		`\.\./\.\./`,
		`\.\./\.\./\.\./`,
		`\.\.\/\.\.\/\.\.\/`,

		// === URL-ENCODED TRAVERSAL ===
		`%2e%2e/`,
		`%2e%2e\\`,
		`%2e%2e%2f`,
		`%252e%252e/`,
		`%252e%252e%252f`,
		`%c0%ae%c0%ae/`, // UTF-8 encoding
		`%c0%ae%c0%ae%c0%af`,

		// === DOUBLE/TRIPLE-ENCODED ===
		`%%32%65%%32%65/`,
		`%25%32%65%25%32%65%25%32%66`,
		`%252e%252e%252f`,

		// === UNIX/LINUX SENSITIVE FILES ===
		`/etc/passwd`,
		`/etc/shadow`,
		`/etc/hosts`,
		`/etc/group`,
		`/etc/issue`,
		`/etc/motd`,
		`/etc/mysql/my.cnf`,
		`/etc/apache2/apache2.conf`,
		`/etc/nginx/nginx.conf`,
		`/etc/ssh/sshd_config`,
		`/etc/crontab`,
		`/etc/fstab`,
		`/etc/resolv.conf`,
		`/etc/hostname`,
		`/etc/network/interfaces`,

		// === PROC FILESYSTEM ===
		`/proc/self/environ`,
		`/proc/self/cmdline`,
		`/proc/self/stat`,
		`/proc/self/status`,
		`/proc/self/fd/`,
		`/proc/version`,
		`/proc/cpuinfo`,
		`/proc/meminfo`,
		`/proc/net/tcp`,
		`/proc/net/udp`,

		// === VAR DIRECTORY ===
		`/var/log/`,
		`/var/log/apache2/`,
		`/var/log/nginx/`,
		`/var/log/mysql/`,
		`/var/log/auth.log`,
		`/var/log/syslog`,
		`/var/log/messages`,
		`/var/www/`,
		`/var/www/html/`,
		`/var/mail/`,
		`/var/spool/`,

		// === USER HOME DIRECTORIES ===
		`/home/.*?/.ssh/`,
		`/home/.*?/.bash_history`,
		`/home/.*?/.bashrc`,
		`/home/.*?/.profile`,
		`/root/.ssh/`,
		`/root/.bash_history`,

		// === WINDOWS SENSITIVE FILES ===
		`(?i)c:\\windows`,
		`(?i)c:\\winnt`,
		`(?i)c:\\windows\\system32`,
		`(?i)c:\\windows\\system32\\config`,
		`(?i)boot\.ini`,
		`(?i)win\.ini`,
		`(?i)system\.ini`,
		`(?i)\\windows\\system32\\drivers\\etc\\hosts`,
		`(?i)\\windows\\repair\\sam`,
		`(?i)\\windows\\system32\\config\\sam`,
		`(?i)\\windows\\system32\\config\\system`,
		`(?i)\\inetpub\\wwwroot\\`,
		`(?i)\\program files\\`,

		// === PHP WRAPPERS ===
		`(?i)php://filter`,
		`(?i)php://input`,
		`(?i)php://output`,
		`(?i)php://fd`,
		`(?i)php://memory`,
		`(?i)php://temp`,
		`(?i)php://stdin`,
		`(?i)php://stdout`,
		`(?i)php://stderr`,
		`(?i)expect://`,
		`(?i)data://`,
		`(?i)zip://`,
		`(?i)zlib://`,
		`(?i)glob://`,
		`(?i)phar://`,

		// === PHP FILTER CHAINS ===
		`(?i)php://filter/convert`,
		`(?i)php://filter/read`,
		`(?i)php://filter/write`,
		`(?i)convert\.base64-encode`,
		`(?i)convert\.base64-decode`,
		`(?i)string\.rot13`,
		`(?i)string\.toupper`,
		`(?i)string\.tolower`,
		`(?i)zlib\.deflate`,
		`(?i)zlib\.inflate`,

		// === NULL BYTE INJECTION ===
		`%00`,
		`\x00`,
		`\0`,
		`\.php%00`,
		`\.txt%00`,

		// === WEB APPLICATION FILES ===
		`(?i)\.env`,
		`(?i)\.git/config`,
		`(?i)\.git/HEAD`,
		`(?i)\.gitignore`,
		`(?i)\.htaccess`,
		`(?i)\.htpasswd`,
		`(?i)web\.config`,
		`(?i)composer\.json`,
		`(?i)package\.json`,
		`(?i)Dockerfile`,
		`(?i)docker-compose\.yml`,
		`(?i)config\.php`,
		`(?i)config\.inc\.php`,
		`(?i)database\.yml`,
		`(?i)settings\.py`,
		`(?i)wp-config\.php`,

		// === LOG FILES ===
		`(?i)access\.log`,
		`(?i)error\.log`,
		`(?i)access_log`,
		`(?i)error_log`,
		`(?i)apache2\.log`,
		`(?i)nginx\.log`,
		`(?i)mysql\.log`,
		`(?i)php_errors\.log`,

		// === SSH KEYS ===
		`(?i)id_rsa`,
		`(?i)id_dsa`,
		`(?i)id_ecdsa`,
		`(?i)id_ed25519`,
		`(?i)authorized_keys`,
		`(?i)known_hosts`,
		`(?i)\.ssh/`,

		// === DATABASE FILES ===
		`(?i)\.db$`,
		`(?i)\.sqlite`,
		`(?i)\.sqlite3`,
		`(?i)database\.db`,

		// === BACKUP FILES ===
		`(?i)\.bak$`,
		`(?i)\.backup$`,
		`(?i)\.old$`,
		`(?i)\.orig$`,
		`(?i)\.save$`,
		`(?i)~$`,

		// === OBFUSCATION WITH SLASHES ===
		`\.\.//`,
		`\.\./\./`,
		`\./\.\./`,
		`//\.\./`,
		`///`,
		`\\\\`,
	}
	
	compiled := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		compiled[i] = regexp.MustCompile(`(?i)` + p)
	}
	
	return &LFIDetector{patterns: compiled}
}

// Detect checks if input contains LFI patterns
func (d *LFIDetector) Detect(input string) (bool, string) {
	normalized := strings.ToLower(input)
	
	for _, pattern := range d.patterns {
		if pattern.MatchString(normalized) {
			return true, "Local File Inclusion pattern detected: " + pattern.String()
		}
	}
	
	return false, ""
}