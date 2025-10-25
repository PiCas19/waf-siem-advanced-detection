package detector

import (
	"regexp"
	"strings"
)

// XXEDetector detects XML External Entity (XXE) attacks
type XXEDetector struct {
	patterns []*regexp.Regexp
}

// NewXXEDetector creates a new XXE detector
func NewXXEDetector() *XXEDetector {
	patterns := []string{
		// === BASIC XXE PATTERNS ===
		`(?i)<!ENTITY`,
		`(?i)<!DOCTYPE.*ENTITY`,
		`(?i)<!DOCTYPE.*\[.*ENTITY`,

		// === SYSTEM KEYWORD (file access) ===
		`(?i)SYSTEM\s+["']file://`,
		`(?i)SYSTEM\s+["']http://`,
		`(?i)SYSTEM\s+["']https://`,
		`(?i)SYSTEM\s+["']ftp://`,
		`(?i)SYSTEM\s+["']/`,
		`(?i)SYSTEM\s+["']\\`,

		// === PUBLIC KEYWORD ===
		`(?i)PUBLIC\s+["']`,

		// === ENTITY REFERENCES ===
		`&[a-zA-Z0-9_]+;`,
		`&#[0-9]+;`,
		`&#x[0-9a-fA-F]+;`,

		// === PARAMETER ENTITIES ===
		`%[a-zA-Z0-9_]+;`,
		`<!ENTITY\s+%`,

		// === BILLION LAUGHS ATTACK (XML Bomb) ===
		`(?i)<!ENTITY.*&.*&.*>`,
		`(?i)<!ENTITY.*<!ENTITY`,

		// === XXE WITH WRAPPER ===
		`(?i)php://filter`,
		`(?i)php://input`,
		`(?i)expect://`,
		`(?i)data://`,

		// === ENTITY EXPANSION ===
		`(?i)<!ENTITY\s+\w+\s+SYSTEM`,
		`(?i)<!ENTITY\s+%\s*\w+\s+SYSTEM`,

		// === EXTERNAL DTD ===
		`(?i)<!DOCTYPE.*SYSTEM`,
		`(?i)<!DOCTYPE.*PUBLIC`,
		`(?i)<!ATTLIST`,

		// === XXE VIA XINCLUDE ===
		`(?i)<xi:include`,
		`(?i)xmlns:xi`,
		`(?i)XInclude`,

		// === XXE VIA SVG ===
		`(?i)<svg.*<!ENTITY`,
		`(?i)<svg.*SYSTEM`,

		// === FILE PATHS IN ENTITIES ===
		`(?i)file:///etc/`,
		`(?i)file:///var/`,
		`(?i)file:///proc/`,
		`(?i)file:///c:/`,
		`(?i)file://localhost/`,

		// === OAST (Out-of-Band) XXE ===
		`(?i)SYSTEM\s+["']http://.*burpcollaborator`,
		`(?i)SYSTEM\s+["']http://.*\.ngrok\.io`,
		`(?i)SYSTEM\s+["']http://.*\.requestbin`,

		// === BLIND XXE ===
		`(?i)<!ENTITY.*%.*SYSTEM.*%`,
		`(?i)%\w+\s*;.*<!ENTITY`,

		// === SOAP XXE ===
		`(?i)<soap:.*<!ENTITY`,
		`(?i)<SOAP-ENV:.*<!ENTITY`,

		// === XXE IN JSON (rare but possible) ===
		`(?i)"<!ENTITY`,
		`(?i)"<!DOCTYPE`,

		// === ENCODED XXE ATTEMPTS ===
		`%3C%21ENTITY`,
		`%3C%21DOCTYPE`,
		`&lt;!ENTITY`,
		`&lt;!DOCTYPE`,

		// === CDATA SECTIONS (used to bypass filters) ===
		`(?i)<!\[CDATA\[.*ENTITY`,
		`(?i)<!\[CDATA\[.*SYSTEM`,

		// === ENTITY WITH NDATA ===
		`(?i)NDATA`,

		// === COMMON VULNERABLE PARSERS ===
		`(?i)<!ENTITY.*file:`,
		`(?i)<!ENTITY.*http:`,
		`(?i)<!ENTITY.*https:`,
		`(?i)<!ENTITY.*ftp:`,

		// === RECURSIVE ENTITY DEFINITIONS ===
		`(?i)<!ENTITY\s+\w+\s+"[^"]*&\w+;`,

		// === XXE WITH DOCUMENT TYPE ===
		`(?i)<!DOCTYPE\s+\w+\s+\[`,
		`(?i)<!DOCTYPE\s+\w+\s+SYSTEM`,

		// === ENTITY WITH DATA URI ===
		`(?i)SYSTEM\s+["']data:`,

		// === XXE IN OFFICE DOCUMENTS ===
		`(?i)<!ENTITY.*Target=`,
		`(?i)<!ENTITY.*TargetMode=`,
	}

	compiled := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		compiled[i] = regexp.MustCompile(p)
	}

	return &XXEDetector{patterns: compiled}
}

// Detect checks if input contains XXE patterns
func (d *XXEDetector) Detect(input string) (bool, string) {
	// Normalize input
	normalized := strings.ToLower(strings.TrimSpace(input))

	// Check if it's XML first (performance optimization)
	if !strings.Contains(input, "<") && !strings.Contains(input, "&#") && !strings.Contains(input, "%3C") {
		return false, ""
	}

	// Check all XXE patterns
	for _, pattern := range d.patterns {
		if pattern.MatchString(input) || pattern.MatchString(normalized) {
			return true, "XML External Entity (XXE) attack detected: " + pattern.String()
		}
	}

	return false, ""
}
