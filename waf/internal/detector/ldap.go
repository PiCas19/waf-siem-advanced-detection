package detector

import (
	"regexp"
	"strings"
)

// LDAPInjectionDetector detects LDAP Injection attacks
type LDAPInjectionDetector struct {
	patterns []*regexp.Regexp
}

// NewLDAPInjectionDetector creates a new LDAP injection detector
func NewLDAPInjectionDetector() *LDAPInjectionDetector {
	patterns := []string{
		// === LDAP FILTER INJECTION ===
		`\*\)\(`,
		`\)\(`,
		`\*\|`,
		`\|\(`,

		// === LDAP WILDCARD INJECTION ===
		`\*`,
		`\(\*\)`,
		`\(cn=\*\)`,
		`\(uid=\*\)`,

		// === LDAP BOOLEAN OPERATORS ===
		`\(\|`,
		`\(&`,
		`\(!`,

		// === AUTHENTICATION BYPASS ===
		`\*\)\(&`,
		`\*\)\(\|`,
		`admin\*`,
		`\*admin\*`,

		// === LDAP FILTER CLOSURE ===
		`\)\)`,
		`\(\(`,
		`\)\(\)`,

		// === ATTRIBUTE INJECTION ===
		`(?i)\(objectClass=\*\)`,
		`(?i)\(cn=\*\)`,
		`(?i)\(uid=\*\)`,
		`(?i)\(sn=\*\)`,
		`(?i)\(mail=\*\)`,

		// === OR INJECTION ===
		`\)\(\|\(`,
		`\*\)\(\|`,
		`\|\(uid=\*`,
		`\|\(cn=\*`,

		// === AND INJECTION ===
		`\)\(&\(`,
		`\*\)\(&`,
		`&\(uid=\*`,
		`&\(cn=\*`,

		// === NOT OPERATOR ===
		`\(!\(`,
		`!\(uid=`,
		`!\(cn=`,

		// === COMMENT INJECTION ===
		`#.*\)`,
		`;.*\)`,

		// === SUBSTRING WILDCARDS ===
		`=\*`,
		`~=\*`,
		`>=\*`,
		`<=\*`,

		// === PRESENCE FILTER ===
		`=\*\)`,
		`\(.*=\*\)`,

		// === COMPARISON OPERATORS ===
		`>=`,
		`<=`,
		`~=`,
		`:=`,

		// === ESCAPE CHARACTER BYPASS ===
		`\\2a`, // * encoded
		`\\28`, // ( encoded
		`\\29`, // ) encoded
		`\\7c`, // | encoded
		`\\26`, // & encoded
		`\\21`, // ! encoded

		// === MULTIPLE CONDITIONS ===
		`\)\)\(`,
		`\(\)\(`,
		`\)\(&\(`,
		`\)\(\|\(`,

		// === ADMIN ACCOUNT ENUMERATION ===
		`(?i)\(cn=admin`,
		`(?i)\(uid=admin`,
		`(?i)\(cn=root`,
		`(?i)\(uid=root`,
		`(?i)\(cn=administrator`,

		// === PASSWORD FIELD ACCESS ===
		`(?i)userPassword`,
		`(?i)unicodePwd`,
		`(?i)password=`,

		// === DISTINGUISHED NAME (DN) INJECTION ===
		`(?i)dc=`,
		`(?i)ou=`,
		`(?i)cn=`,
		`(?i)uid=`,

		// === LDAP SEARCH FILTER BYPASS ===
		`\(\|.*\)\)`,
		`\(&.*\)\)`,
		`\(!.*\)\)`,

		// === BLIND LDAP INJECTION ===
		`\(cn=a\*\)`,
		`\(cn=b\*\)`,
		`\(uid=a\*\)`,

		// === URL ENCODED LDAP CHARACTERS ===
		`%28`, // (
		`%29`, // )
		`%2a`, // *
		`%7c`, // |
		`%26`, // &

		// === DOUBLE ENCODED ===
		`%2528`, // %%28 -> %28 -> (
		`%2529`, // %%29 -> %29 -> )

		// === ATTRIBUTE VALUE ASSERTION ===
		`\([^)]*=[^)]*\*`,
		`\([^)]*~=[^)]*`,
		`\([^)]*>=[^)]*`,
		`\([^)]*<=[^)]*`,

		// === NESTED FILTERS ===
		`\(\|.*\(.*\).*\)`,
		`\(&.*\(.*\).*\)`,

		// === LDAP INJECTION WITH SPACES ===
		`\(\s*\|\s*`,
		`\(\s*&\s*`,
		`\(\s*!\s*`,

		// === ATTRIBUTE TYPE INJECTION ===
		`(?i)objectClass=\*`,
		`(?i)memberOf=`,
		`(?i)member=`,

		// === TIME-BASED BLIND INJECTION ===
		`\(cn=.*\)\(`,
		`\(uid=.*\)\(`,

		// === LDAP ANONYMOUS BIND ===
		`\(\)`,
		`\(&\(\)\)`,
		`\(\|\(\)\)`,
	}

	compiled := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		compiled[i] = regexp.MustCompile(p)
	}

	return &LDAPInjectionDetector{patterns: compiled}
}

// Detect checks if input contains LDAP injection patterns
func (d *LDAPInjectionDetector) Detect(input string) (bool, string) {
	// Check if input contains LDAP-like syntax
	if !strings.Contains(input, "(") && !strings.Contains(input, "*") && !strings.Contains(input, ")") {
		return false, ""
	}

	// Check all patterns
	for _, pattern := range d.patterns {
		if pattern.MatchString(input) {
			return true, "LDAP Injection attack detected: " + pattern.String()
		}
	}

	return false, ""
}
