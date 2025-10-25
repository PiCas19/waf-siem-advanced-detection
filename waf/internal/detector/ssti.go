package detector

import (
	"regexp"
	"strings"
)

type SSTIDetector struct {
	patterns []*regexp.Regexp
}

func NewSSTIDetector() *SSTIDetector {
	patterns := []string{
		`\{\{.*?\}\}`,
		`\{\%.*?\%\}`,
		`\$\{.*?\}`,
		`<%.*%>`,
		`(?i)\{\{.*__class__.*\}\}`,
		`(?i)\{\{.*config.*\}\}`,
		`(?i)\{\{.*request.*\}\}`,
		`<#.*#>`,
		`#set`,
		`\{php\}`,
	}
	
	compiled := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		compiled[i] = regexp.MustCompile(p)
	}
	
	return &SSTIDetector{patterns: compiled}
}

func (d *SSTIDetector) Detect(input string) (bool, string) {
	if !strings.Contains(input, "{{") && !strings.Contains(input, "{%") && !strings.Contains(input, "${") && !strings.Contains(input, "<%") {
		return false, ""
	}
	
	for _, pattern := range d.patterns {
		if pattern.MatchString(input) {
			return true, "Server-Side Template Injection attack detected"
		}
	}
	
	return false, ""
}