package detector

import (
	"html"
	"regexp"
	"strings"
)

// XSSDetector detects Cross-Site Scripting attacks
type XSSDetector struct {
	patterns []*regexp.Regexp
}

// NewXSSDetector creates a new XSS detector
func NewXSSDetector() *XSSDetector {
	patterns := []string{
		// === SCRIPT TAGS (BASIC & OBFUSCATED) ===
		`<script[^>]*>.*?</script>`,
		`<script[^>]*>`,
		`<script[\s/\\]+`, // Obfuscated: <script/ >
		`<script>`,
		`</script>`,

		// === JAVASCRIPT/VBSCRIPT PROTOCOLS ===
		`javascript:`,
		`vbscript:`,
		`data:text/javascript`,
		`livescript:`,

		// === EVENT HANDLERS (COMPREHENSIVE LIST) ===
		`on\w+\s*=`,
		`onload\s*=`,
		`onerror\s*=`,
		`onclick\s*=`,
		`onmouseover\s*=`,
		`onmouseout\s*=`,
		`onmousemove\s*=`,
		`onmouseenter\s*=`,
		`onmouseleave\s*=`,
		`onfocus\s*=`,
		`onblur\s*=`,
		`onchange\s*=`,
		`onsubmit\s*=`,
		`onkeydown\s*=`,
		`onkeyup\s*=`,
		`onkeypress\s*=`,
		`ondblclick\s*=`,
		`oncontextmenu\s*=`,
		`oninput\s*=`,
		`onselect\s*=`,
		`onscroll\s*=`,
		`ondrag\s*=`,
		`ondrop\s*=`,
		`oncut\s*=`,
		`oncopy\s*=`,
		`onpaste\s*=`,
		`onabort\s*=`,
		`oncanplay\s*=`,
		`onended\s*=`,
		`onwaiting\s*=`,
		`onwheel\s*=`,
		`ontoggle\s*=`,
		`onanimationstart\s*=`,
		`onanimationend\s*=`,
		`onanimationiteration\s*=`,
		`ontransitionend\s*=`,

		// === DANGEROUS TAGS ===
		`<iframe`,
		`<object`,
		`<embed`,
		`<applet`,
		`<meta`,
		`<link`,
		`<base`,
		`<form`,
		`<input`,
		`<button`,
		`<select`,
		`<textarea`,
		`<details`,
		`<dialog`,
		`<marquee`,
		`<bgsound`,

		// === JAVASCRIPT FUNCTIONS ===
		`eval\s*\(`,
		`expression\s*\(`,
		`setTimeout\s*\(`,
		`setInterval\s*\(`,
		`Function\s*\(`,
		`constructor\s*\(`,
		`alert\s*\(`,
		`prompt\s*\(`,
		`confirm\s*\(`,
		`document\.write\s*\(`,
		`document\.writeln\s*\(`,
		`window\.location`,
		`document\.location`,
		`document\.cookie`,
		`window\.open\s*\(`,

		// === SVG/XML ATTACKS ===
		`<svg[^>]*onload`,
		`<svg[^>]*onerror`,
		`<img[^>]*onerror`,
		`<img[^>]*onload`,
		`<body[^>]*onload`,
		`<body[^>]*onerror`,
		`<video[^>]*onerror`,
		`<audio[^>]*onerror`,
		`<source[^>]*onerror`,
		`<track[^>]*onerror`,
		`<image[^>]*onerror`,
		`<animatetransform[^>]*onbegin`,
		`<set[^>]*onbegin`,

		// === DATA URIs WITH DANGEROUS CONTENT ===
		`data:text/html`,
		`data:application/javascript`,
		`data:application/x-javascript`,
		`data:text/javascript`,
		`data:image/svg\+xml`,

		// === OBFUSCATION TECHNIQUES ===
		`&#[0-9]+;`, // HTML entity encoding
		`&#x[0-9a-f]+;`, // Hex HTML entities
		`\\x[0-9a-f]{2}`, // Hex escape sequences
		`\\u[0-9a-f]{4}`, // Unicode escape sequences
		`%3cscript`, // URL encoded <script
		`%3c%73%63%72%69%70%74`, // Double URL encoded
		`\+alert\+`, // Space replacement with +
		`fromCharCode`, // String.fromCharCode obfuscation
		`atob\s*\(`, // Base64 decoding

		// === STYLE ATTRIBUTE ATTACKS ===
		`style\s*=.*?expression\s*\(`,
		`style\s*=.*?javascript:`,
		`style\s*=.*?@import`,
		`style\s*=.*?behavior:`,
		`-moz-binding:`,

		// === IMPORT STATEMENTS ===
		`@import`,
		`<link[^>]*href.*?javascript:`,
		`<link[^>]*import`,

		// === TEMPLATE INJECTION ===
		`\{\{.*?\}\}`, // Angular/Vue templates
		`<%.*?%>`, // JSP/ASP templates
		`\${.*?}`, // Template literals
	}
	
	compiled := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		compiled[i] = regexp.MustCompile(`(?i)` + p)
	}
	
	return &XSSDetector{patterns: compiled}
}

// Detect checks if input contains XSS patterns
func (d *XSSDetector) Detect(input string) (bool, string) {
	// Decode HTML entities
	decoded := html.UnescapeString(input)
	
	// Also check URL-decoded version
	urlDecoded := strings.ReplaceAll(decoded, "%3C", "<")
	urlDecoded = strings.ReplaceAll(urlDecoded, "%3E", ">")
	urlDecoded = strings.ReplaceAll(urlDecoded, "%20", " ")
	
	// Normalize to lowercase for case-insensitive matching
	normalized := strings.ToLower(urlDecoded)
	
	for _, pattern := range d.patterns {
		if pattern.MatchString(normalized) {
			return true, "XSS pattern detected: " + pattern.String()
		}
	}
	
	return false, ""
}