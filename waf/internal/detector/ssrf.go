package detector

import (
	"regexp"
	"strings"
)

// SSRFDetector detects Server-Side Request Forgery (SSRF) attacks
type SSRFDetector struct {
	patterns []*regexp.Regexp
}

// NewSSRFDetector creates a new SSRF detector
func NewSSRFDetector() *SSRFDetector {
	patterns := []string{
		// === LOCALHOST/LOOPBACK ===
		`(?i)https?://localhost`,
		`(?i)https?://127\.0\.0\.1`,
		`(?i)https?://0\.0\.0\.0`,
		`(?i)https?://\[::1\]`,
		`(?i)https?://\[0:0:0:0:0:0:0:1\]`,
		`(?i)https?://0000::1`,
		`(?i)https?://\[::ffff:127\.0\.0\.1\]`,

		// === LOCALHOST VARIATIONS (obfuscation) ===
		`(?i)https?://127\.1`,
		`(?i)https?://127\.0\.1`,
		`(?i)https?://2130706433`, // 127.0.0.1 in decimal
		`(?i)https?://017700000001`, // 127.0.0.1 in octal
		`(?i)https?://0x7f000001`, // 127.0.0.1 in hex
		`(?i)https?://0x7f\.0x0\.0x0\.0x1`,
		`(?i)https?://localhost\.localdomain`,

		// === PRIVATE IP RANGES (RFC 1918) ===
		// 10.0.0.0/8
		`(?i)https?://10\.`,
		`(?i)https?://10\.\d+\.\d+\.\d+`,

		// 172.16.0.0/12
		`(?i)https?://172\.1[6-9]\.`,
		`(?i)https?://172\.2[0-9]\.`,
		`(?i)https?://172\.3[0-1]\.`,

		// 192.168.0.0/16
		`(?i)https?://192\.168\.`,

		// === LINK-LOCAL ADDRESSES ===
		`(?i)https?://169\.254\.`,
		`(?i)https?://\[fe80::`,
		`(?i)https?://\[fe80:`,

		// === CLOUD METADATA SERVICES ===
		// AWS
		`(?i)169\.254\.169\.254`,
		`(?i)https?://169\.254\.169\.254`,
		`(?i)instance-data`,
		`(?i)/latest/meta-data`,
		`(?i)/latest/user-data`,
		`(?i)/latest/dynamic`,

		// Google Cloud
		`(?i)metadata\.google\.internal`,
		`(?i)metadata\.goog`,
		`(?i)http://metadata`,

		// Azure
		`(?i)169\.254\.169\.254/metadata`,
		`(?i)metadata\.azure\.com`,

		// Digital Ocean
		`(?i)169\.254\.169\.254/metadata`,

		// Oracle Cloud
		`(?i)169\.254\.169\.254/opc`,

		// === INTERNAL DOMAIN NAMES ===
		`(?i)https?://internal`,
		`(?i)https?://intranet`,
		`(?i)https?://.*\.internal`,
		`(?i)https?://.*\.local`,
		`(?i)https?://.*\.lan`,
		`(?i)https?://.*\.corp`,

		// === REDIRECT ATTEMPTS ===
		`(?i)@localhost`,
		`(?i)@127\.0\.0\.1`,
		`(?i)@10\.`,
		`(?i)@192\.168\.`,

		// === URL WITH INTERNAL IPS IN QUERY/PATH ===
		`(?i)[?&](url|uri|path|dest|redirect|target)=.*?https?://127\.`,
		`(?i)[?&](url|uri|path|dest|redirect|target)=.*?https?://localhost`,
		`(?i)[?&](url|uri|path|dest|redirect|target)=.*?https?://10\.`,
		`(?i)[?&](url|uri|path|dest|redirect|target)=.*?https?://192\.168\.`,

		// === FILE PROTOCOL (local file access) ===
		`(?i)file:///`,
		`(?i)file://localhost/`,
		`(?i)file://127\.0\.0\.1/`,

		// === SPECIAL PROTOCOLS ===
		`(?i)dict://`,
		`(?i)gopher://`,
		`(?i)ldap://localhost`,
		`(?i)ldap://127\.0\.0\.1`,

		// === URL ENCODING BYPASS ===
		`(?i)https?://%31%32%37%2e%30%2e%30%2e%31`, // 127.0.0.1
		`(?i)https?://%6c%6f%63%61%6c%68%6f%73%74`, // localhost

		// === ALTERNATE ENCODING ===
		`(?i)https?://①②⑦.⓪.⓪.①`, // Unicode
		`(?i)https?://0177\.0\.0\.01`, // Octal

		// === DNS REBINDING ===
		`(?i)\.burpcollaborator\.net`,
		`(?i)\.ngrok\.io`,
		`(?i)\.localtunnel\.me`,
		`(?i)\.tunnel\.com`,

		// === BYPASS WITH @  ===
		`(?i)https?://.*@127\.`,
		`(?i)https?://.*@localhost`,
		`(?i)https?://.*@10\.`,
		`(?i)https?://.*@192\.168\.`,

		// === BYPASS WITH # (fragment) ===
		`(?i)https?://[^/]+#127\.`,
		`(?i)https?://[^/]+#localhost`,

		// === BYPASS WITH DOTS/SLASHES ===
		`(?i)https?://127。0。0。1`, // Alternate dots
		`(?i)https?://127%2e0%2e0%2e1`,
		`(?i)https?://127\.0\.0。1`,

		// === WEBHOOKS/CALLBACKS TO INTERNAL ===
		`(?i)(callback|webhook|notify|ping|healthcheck)=.*?https?://127\.`,
		`(?i)(callback|webhook|notify|ping|healthcheck)=.*?https?://localhost`,
		`(?i)(callback|webhook|notify|ping|healthcheck)=.*?https?://10\.`,

		// === PORT SCANNING ===
		`(?i)https?://127\.0\.0\.1:\d+`,
		`(?i)https?://localhost:\d+`,
		`(?i)https?://10\.\d+\.\d+\.\d+:\d+`,

		// === SERVICE DISCOVERY ===
		`(?i)https?://consul`,
		`(?i)https?://etcd`,
		`(?i)https?://zookeeper`,
		`(?i)https?://kubernetes`,
		`(?i)https?://docker`,

		// === CLOUD SERVICES ===
		`(?i)s3\.amazonaws\.com`,
		`(?i)amazonaws\.com/.*credentials`,
		`(?i)storage\.googleapis\.com`,
		`(?i)blob\.core\.windows\.net`,

		// === SSRF VIA REDIRECTS ===
		`(?i)(redirect|redir|url|uri|next|goto|target)=.*?127\.`,
		`(?i)(redirect|redir|url|uri|next|goto|target)=.*?localhost`,
		`(?i)(redirect|redir|url|uri|next|goto|target)=.*?10\.`,

		// === SSRF WITH DATA EXFILTRATION ===
		`(?i)https?://.*?:(22|23|25|80|443|445|3306|3389|5432|6379|8080|8443|9200)`,

		// === BINARY/OCTAL/HEX IP BYPASS ===
		`(?i)https?://0x[0-9a-f]{1,8}`, // Hex IP
		`(?i)https?://[0-9]{8,10}`, // Decimal IP
		`(?i)https?://0[0-7]+\.[0-7]+`, // Octal

		// === SSRF IN XML/SVG ===
		`(?i)<svg.*href=["']https?://127\.`,
		`(?i)<svg.*href=["']https?://localhost`,
		`(?i)<image.*href=["']https?://127\.`,

		// === LOCALHOST ALTERNATIVE NAMES ===
		`(?i)https?://localhost\.localdomain`,
		`(?i)https?://broadcasthost`,
		`(?i)https?://ip6-localhost`,
		`(?i)https?://ip6-loopback`,

		// === SSRF WITH AUTHENTICATION ===
		`(?i)https?://.*:.*@127\.`,
		`(?i)https?://.*:.*@localhost`,
		`(?i)https?://.*:.*@10\.`,
	}

	compiled := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		compiled[i] = regexp.MustCompile(p)
	}

	return &SSRFDetector{patterns: compiled}
}

// Detect checks if input contains SSRF patterns
func (d *SSRFDetector) Detect(input string) (bool, string) {
	// Check all patterns
	for _, pattern := range d.patterns {
		if pattern.MatchString(input) {
			return true, "Server-Side Request Forgery (SSRF) attack detected: " + pattern.String()
		}
	}

	return false, ""
}
