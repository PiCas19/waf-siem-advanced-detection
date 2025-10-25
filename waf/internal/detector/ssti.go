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
		// Jinja2/Flask
		`(?i)\{\{.*__(class|mro|subclasses|globals|builtins|import)__.*\}\}`,
		`(?i)\{\{.*config.*\}\}`,
		`(?i)\{\{.*request\..*\}\}`,
		
		// Template tags con codice
		`\{\%.*import.*\%\}`,
		`\{\%.*exec.*\%\}`,
		
		// Other template engines
		`(?i)\$\{.*\.(execute|runtime|class).*\}`,
		`<%.*eval.*%>`,
		`<%.*exec.*%>`,
		
		// Freemarker
		`<#.*execute.*#>`,
		`<#assign.*>`,
	}
	
	compiled := make([]*regexp.Regexp, 0)
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err == nil {
			compiled = append(compiled, re)
		}
	}
	
	return &SSTIDetector{patterns: compiled}
}

func (d *SSTIDetector) Detect(input string) (bool, string) {
	// Check solo se ha template syntax
	if !strings.Contains(input, "{{") &&
	   !strings.Contains(input, "{%") &&
	   !strings.Contains(input, "<%") &&
	   !strings.Contains(input, "<#") {
		return false, ""
	}
	
	// Ignora JSON normale
	if strings.HasPrefix(input, "{") && strings.HasSuffix(input, "}") &&
	   !strings.Contains(input, "{{") && !strings.Contains(input, "__") {
		return false, ""
	}
	
	for _, pattern := range d.patterns {
		if pattern.MatchString(input) {
			return true, "Server-Side Template Injection attack detected"
		}
	}
	
	return false, ""
}
