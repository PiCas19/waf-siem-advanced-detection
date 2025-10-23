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
		// Script tags
		`<script[^>]*>.*?</script>`,
		`<script[^>]*>`,
		
		// JavaScript protocol
		`javascript:`,
		`vbscript:`,
		
		// Event handlers
		`on\w+\s*=`,
		`onload\s*=`,
		`onerror\s*=`,
		`onclick\s*=`,
		`onmouseover\s*=`,
		
		// Dangerous tags
		`<iframe`,
		`<object`,
		`<embed`,
		`<applet`,
		
		// JavaScript functions
		`eval\s*\(`,
		`expression\s*\(`,
		`setTimeout\s*\(`,
		`setInterval\s*\(`,
		
		// SVG/XML attacks
		`<svg[^>]*onload`,
		`<img[^>]*onerror`,
		`<body[^>]*onload`,
		
		// Data URIs with JavaScript
		`data:text/html`,
		`data:application/javascript`,
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