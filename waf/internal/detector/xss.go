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
		// Script tags completi
		`(?i)<script[^>]*>.*</script>`,
		`(?i)<script[^>]*>`,
		`(?i)</script>`,
		
		// Protocolli pericolosi
		`(?i)javascript\s*:`,
		`(?i)vbscript\s*:`,
		`(?i)data\s*:\s*text/html`,
		
		// Event handlers con assegnazione
		`(?i)on(load|error|click|mouseover|focus|blur|change|submit|keydown|keyup)\s*=\s*[^>]*`,
		
		// Tag pericolosi con attributi sospetti
		`(?i)<iframe[^>]*(src|onload)\s*=`,
		`(?i)<object[^>]*(data|type)\s*=`,
		`(?i)<embed[^>]*src\s*=`,
		`(?i)<img[^>]*onerror\s*=`,
		`(?i)<svg[^>]*onload\s*=`,
		`(?i)<body[^>]*onload\s*=`,
		
		// Funzioni JS pericolose con parentesi
		`(?i)eval\s*\(`,
		`(?i)expression\s*\(`,
		`(?i)setTimeout\s*\(`,
		`(?i)setInterval\s*\(`,
		`(?i)(alert|prompt|confirm)\s*\(`,
		
		// Encoded XSS
		`(?i)%3cscript`,
		`(?i)&#60;script`,
		`(?i)&lt;script`,
	}
	
	compiled := make([]*regexp.Regexp, 0)
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err == nil {
			compiled = append(compiled, re)
		}
	}
	
	return &XSSDetector{patterns: compiled}
}

func (d *XSSDetector) Detect(input string) (bool, string) {
	// Ignora input molto corti
	if len(input) < 5 {
		return false, ""
	}
	
	// Decode HTML entities
	decoded := html.UnescapeString(input)
	
	// URL decode
	urlDecoded := strings.ReplaceAll(decoded, "%3C", "<")
	urlDecoded = strings.ReplaceAll(urlDecoded, "%3E", ">")
	urlDecoded = strings.ReplaceAll(urlDecoded, "%3c", "<")
	urlDecoded = strings.ReplaceAll(urlDecoded, "%3e", ">")
	
	normalized := strings.ToLower(urlDecoded)
	
	// Check solo se contiene caratteri sospetti
	if !strings.Contains(normalized, "<") && 
	   !strings.Contains(normalized, "javascript:") && 
	   !strings.Contains(normalized, "on") {
		return false, ""
	}
	
	for _, pattern := range d.patterns {
		if pattern.MatchString(normalized) {
			return true, "XSS pattern detected"
		}
	}
	
	return false, ""
}
