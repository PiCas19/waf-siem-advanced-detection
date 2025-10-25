package detector

import (
	"html"
	"regexp"
	"strings"
)

type XSSDetector struct {
	patterns []*regexp.Regexp
}

func NewXSSDetector() *XSSDetector {
	patterns := []string{
		`(?i)<script[^>]*>`,
		`(?i)</script>`,
		`(?i)javascript:`,
		`(?i)vbscript:`,
		`(?i)on[a-z]+\s*=`,
		`(?i)onload\s*=`,
		`(?i)onerror\s*=`,
		`(?i)onclick\s*=`,
		`(?i)onmouseover\s*=`,
		`(?i)<iframe`,
		`(?i)<object`,
		`(?i)<embed`,
		`(?i)<applet`,
		`(?i)eval\s*\(`,
		`(?i)setTimeout\s*\(`,
		`(?i)setInterval\s*\(`,
		`(?i)<svg[^>]*onload`,
		`(?i)<img[^>]*onerror`,
		`(?i)<body[^>]*onload`,
		`(?i)data:text/html`,
		`(?i)data:application/javascript`,
	}
	
	compiled := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		compiled[i] = regexp.MustCompile(p)
	}
	
	return &XSSDetector{patterns: compiled}
}

func (d *XSSDetector) Detect(input string) (bool, string) {
	decoded := html.UnescapeString(input)
	urlDecoded := strings.ReplaceAll(decoded, "%3C", "<")
	urlDecoded = strings.ReplaceAll(urlDecoded, "%3E", ">")
	normalized := strings.ToLower(urlDecoded)
	
	for _, pattern := range d.patterns {
		if pattern.MatchString(normalized) {
			return true, "XSS pattern detected"
		}
	}
	
	return false, ""
}