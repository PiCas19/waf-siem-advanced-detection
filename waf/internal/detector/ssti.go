package detector

import (
	"regexp"
	"strings"
)

// SSTIDetector detects Server-Side Template Injection attacks
type SSTIDetector struct {
	patterns []*regexp.Regexp
}

// NewSSTIDetector creates a new SSTI detector
func NewSSTIDetector() *SSTIDetector {
	patterns := []string{
		// === JINJA2 / FLASK (Python) ===
		`\{\{.*?\}\}`,
		`\{\%.*?\%\}`,
		`\{\{.*config.*\}\}`,
		`\{\{.*request.*\}\}`,
		`\{\{.*__class__.*\}\}`,
		`\{\{.*__mro__.*\}\}`,
		`\{\{.*__subclasses__.*\}\}`,
		`\{\{.*__globals__.*\}\}`,
		`\{\{.*__init__.*\}\}`,
		`\{\{.*__import__.*\}\}`,
		`\{\{.*popen.*\}\}`,
		`\{\{.*os\..*\}\}`,
		`\{\{.*lipsum.*\}\}`,
		`\{\{.*cycler.*\}\}`,
		`\{\{.*joiner.*\}\}`,
		`\{\{.*namespace.*\}\}`,

		// === FREEMARKER (Java) ===
		`\$\{.*?\}`,
		`<#.*?>`,
		`<#.*#>`,
		`<@.*@>`,
		`\$\{.*\.class.*\}`,
		`\$\{.*exec.*\}`,
		`\$\{.*Runtime.*\}`,
		`<#assign`,
		`<#import`,
		`<#include`,
		`freemarker\.template`,

		// === VELOCITY (Java) ===
		`#set`,
		`#if`,
		`#foreach`,
		`#include`,
		`#parse`,
		`#macro`,
		`\$\{.*\.class\..*\}`,
		`\$\{.*Class\.forName.*\}`,

		// === SMARTY (PHP) ===
		`\{.*\}`,
		`\{\$.*\}`,
		`\{php\}`,
		`\{/php\}`,
		`\{literal\}`,
		`\{include`,
		`\{eval`,
		`\{assign`,
		`self::`,
		`static::`,

		// === TWIG (PHP) ===
		`\{\{.*_self.*\}\}`,
		`\{\{.*_context.*\}\}`,
		`\{\{.*app.*\}\}`,
		`\{\{.*_charset.*\}\}`,
		`\{\{.*attribute.*\}\}`,
		`\{\{.*constant.*\}\}`,
		`\{\{.*filter.*\}\}`,
		`\{\{.*function.*\}\}`,
		`\{\{.*map.*\}\}`,
		`\{\{.*reduce.*\}\}`,
		`\{\{.*system.*\}\}`,
		`\{\{.*passthru.*\}\}`,
		`\{\{.*exec.*\}\}`,

		// === ERB (Ruby) ===
		`<%.*%>`,
		`<%=.*%>`,
		`<%#.*%>`,
		`<%.*system.*%>`,
		`<%.*eval.*%>`,
		`<%.*exec.*%>`,
		`<%.*\`.*\`.*%>`,
		`<%.*File\.read.*%>`,

		// === HANDLEBARS (JavaScript) ===
		`\{\{.*\}\}`,
		`\{\{.*\.\.\/.*\}\}`,
		`\{\{.*prototype.*\}\}`,
		`\{\{.*constructor.*\}\}`,
		`\{\{.*__proto__.*\}\}`,

		// === PUG/JADE (Node.js) ===
		`-\s*var`,
		`-\s*eval`,
		`-\s*require`,
		`-\s*process`,
		`#\{.*\}`,
		`!\{.*\}`,

		// === TORNADO (Python) ===
		`\{\{.*handler.*\}\}`,
		`\{\{.*settings.*\}\}`,
		`\{\{.*application.*\}\}`,
		`\{\{.*request.*\}\}`,
		`\{\{.*subprocess.*\}\}`,

		// === NUNJUCKS (Node.js) ===
		`\{\{.*env.*\}\}`,
		`\{\{.*ctx.*\}\}`,
		`\{\{.*range.*\}\}`,
		`\{\{.*global.*\}\}`,

		// === THYMELEAF (Java) ===
		`\$\{.*@.*\}`,
		`th:.*=`,
		`\*\{.*\}`,
		`@\{.*\}`,

		// === GROOVY (Java) ===
		`\$\{.*\.execute\(\).*\}`,
		`\$\{.*".*".execute\(\).*\}`,
		`\$\{.*Runtime.*\}`,

		// === COMMON RCE PATTERNS IN TEMPLATES ===
		`\{\{.*eval.*\}\}`,
		`\{\{.*exec.*\}\}`,
		`\{\{.*system.*\}\}`,
		`\{\{.*popen.*\}\}`,
		`\{\{.*shell_exec.*\}\}`,
		`\{\{.*passthru.*\}\}`,
		`\{\{.*proc_open.*\}\}`,

		// === PYTHON-SPECIFIC ===
		`\{\{.*__builtins__.*\}\}`,
		`\{\{.*__dict__.*\}\}`,
		`\{\{.*__name__.*\}\}`,
		`\{\{.*__file__.*\}\}`,
		`\{\{.*\[\d+\]\..*\}\}`,
		`\{\{.*\(\)\..*\}\}`,

		// === FILE ACCESS ===
		`\{\{.*open\(.*\).*\}\}`,
		`\{\{.*read\(.*\).*\}\}`,
		`\{\{.*file\(.*\).*\}\}`,
		`\$\{.*File\..*\}`,
		`<%.*File\..*%>`,

		// === REFLECTION / CLASS ACCESS ===
		`\.class\.forName`,
		`\.class\.getMethod`,
		`\.getRuntime\(\)`,
		`\.invoke\(`,

		// === SPECIAL FUNCTIONS ===
		`\{\{.*lipsum\.__globals__.*\}\}`,
		`\{\{.*url_for\.__globals__.*\}\}`,
		`\{\{.*get_flashed_messages\.__globals__.*\}\}`,
		`\{\{.*dict\.__subclasses__.*\}\}`,

		// === ENCODED PAYLOADS ===
		`%7B%7B`, // {{
		`%7D%7D`, // }}
		`%7B%25`, // {%
		`%25%7D`, // %}

		// === NESTED TEMPLATES ===
		`\{\{.*\{\{.*\}\}.*\}\}`,
		`\$\{.*\$\{.*\}.*\}`,

		// === FILTER BYPASS ===
		`\[\]\..*\..*`,
		`\[\]\..*\(\)`,
		`\|\s*attr`,
		`\|\s*select`,
		`\|\s*map`,
		`\|\s*list`,
	}

	compiled := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		compiled[i] = regexp.MustCompile(`(?i)` + p)
	}

	return &SSTIDetector{patterns: compiled}
}

// Detect checks if input contains SSTI patterns
func (d *SSTIDetector) Detect(input string) (bool, string) {
	// Check if input contains template-like syntax
	if !strings.Contains(input, "{{") && !strings.Contains(input, "{%") &&
		!strings.Contains(input, "${") && !strings.Contains(input, "<%") &&
		!strings.Contains(input, "#{") {
		return false, ""
	}

	// Check all patterns
	for _, pattern := range d.patterns {
		if pattern.MatchString(input) {
			return true, "Server-Side Template Injection (SSTI) attack detected: " + pattern.String()
		}
	}

	return false, ""
}
