package detector

import (
	"regexp"
	"strings"
)

// PathTraversalDetector detects advanced Path Traversal attacks
type PathTraversalDetector struct {
	patterns []*regexp.Regexp
}

// NewPathTraversalDetector creates a new advanced Path Traversal detector
func NewPathTraversalDetector() *PathTraversalDetector {
	patterns := []string{
		// === BASIC PATH TRAVERSAL ===
		`\.\./`,
		`\.\.\\`,
		`\.\./\.\./`,
		`\.\./\.\./\.\./`,
		`\.\.\/\.\.\/\.\.\/`,

		// === URL ENCODED (Single) ===
		`%2e%2e/`,
		`%2e%2e\\`,
		`%2e%2e%2f`,
		`%2e%2e%5c`,

		// === URL ENCODED (Double) ===
		`%252e%252e/`,
		`%252e%252e%252f`,
		`%252e%252e%255c`,

		// === UTF-8 ENCODED ===
		`%c0%2e%c0%2e/`,
		`%c0%ae%c0%ae/`,
		`%c0%ae%c0%ae%c0%af`,

		// === OVERLONG UTF-8 ===
		`%e0%80%ae%e0%80%ae/`,
		`%c0%2e%c0%2e%c0%2f`,

		// === 16-BIT UNICODE ===
		`%u002e%u002e/`,
		`%u002e%u002e%u002f`,

		// === UNC PATH (Windows) ===
		`\\\\`,
		`%5c%5c`,
		`\\\\?\\`,

		// === MIXED SEPARATORS ===
		`\.\.\/`,
		`\.\.\\/`,
		`\.\.//`,
		`\.\./\\`,

		// === ABSOLUTE PATHS ===
		`^/etc/`,
		`^/var/`,
		`^/proc/`,
		`^/sys/`,
		`^/root/`,
		`^/home/`,
		`^c:/`,
		`^c:\\`,

		// === DOUBLE SLASHES ===
		`//`,
		`///`,
		`////`,
		`\\\\`,
		`\\\\\\\`,

		// === CURRENT DIRECTORY ===
		`\./`,
		`\.\\`,
		`\./\./`,

		// === NULL BYTE INJECTION ===
		`%00`,
		`\x00`,
		`\0`,
		`\.\./%00`,
		`\.\./\x00`,

		// === DOT SEGMENTS ===
		`\.`,
		`\.\.`,
		`\.\.\.$`,
		`\.{2,}`,

		// === ENCODED SLASHES ===
		`%2f`,
		`%2F`,
		`%5c`,
		`%5C`,

		// === BACKSLASH NORMALIZATION ===
		`\.\.%5c`,
		`%2e%2e%5c`,

		// === NESTED ENCODING ===
		`%252f`,
		`%252F`,
		`%255c`,
		`%255C`,

		// === UNICODE SLASHES ===
		`\u2215`, // ∕
		`\u2216`, // ∖
		`\u2044`, // ⁄
		`%u2215`,
		`%u2216`,

		// === SPACE BYPASS ===
		`\.\. /`,
		`\. \./`,
		`\. \. /`,

		// === TAB BYPASS ===
		`\.\.\t/`,
		`\.\t\./`,

		// === WILDCARD TRAVERSAL ===
		`\*\.\./`,
		`\.\./\*`,

		// === RELATIVE PATH WITH FILENAME ===
		`\.\./.*\.(php|asp|aspx|jsp|conf|ini|xml|json|yml|yaml|env|config|bak)`,

		// === WINDOWS DRIVE LETTERS ===
		`[a-zA-Z]:/`,
		`[a-zA-Z]:\\`,
		`%[0-9a-fA-F]{2}:/`,

		// === DEVICE FILES (Windows) ===
		`(?i)con\.`,
		`(?i)prn\.`,
		`(?i)aux\.`,
		`(?i)nul\.`,
		`(?i)com[1-9]\.`,
		`(?i)lpt[1-9]\.`,

		// === STREAM ALTERNATE DATA STREAMS (Windows) ===
		`::\$DATA`,
		`::\$INDEX_ALLOCATION`,

		// === PHP WRAPPERS WITH TRAVERSAL ===
		`php://filter.*\.\./`,
		`php://input.*\.\./`,
		`expect://.*\.\./`,

		// === ENCODING COMBINATIONS ===
		`%2e\.`,
		`\.%2e`,
		`%2e%2e`,

		// === REVERSE TRAVERSAL ===
		`/\.\./`,
		`/\.\.\\`,
		`\\/\.\./`,

		// === ABSOLUTE PATH WITH TRAVERSAL ===
		`/.*\.\./`,
		`c:\\.*\\\.\.`,

		// === CHAINED TRAVERSAL ===
		`(\.\./){2,}`,
		`(\.\.\\){2,}`,
		`(%2e%2e/){2,}`,

		// === ENCODED DOTS ===
		`%2e\./`,
		`\.%2e/`,
		`%2e%2e/`,

		// === OBFUSCATED SEPARATORS ===
		`\.\.;/`,
		`\.\.%00/`,
		`\.\.%20/`,

		// === UNUSUAL ENCODINGS ===
		`%%32%65%%32%65/`,
		`%c0%af`,
		`%c1%9c`,

		// === PATH PARAMETER POLLUTION ===
		`;.*\.\./`,
		`;.*%2e%2e`,

		// === ZIP SLIP ===
		`\.\.\\.*\.zip`,
		`\.\./.*\.tar`,
		`\.\./.*\.gz`,

		// === SYMLINK TRAVERSAL ===
		`/proc/self/cwd`,
		`/proc/self/root`,
		`/proc/self/fd/`,

		// === TRIPLE DOT (unusual) ===
		`\.\.\.`,
		`%2e%2e%2e`,

		// === PARSER CONFUSION ===
		`\./\.\./`,
		`\.\//\.\./`,
		`\.\/\.\/\.\./`,

		// === BACKSLASH FORWARD SLASH MIX ===
		`\.\.\/\.\.\\`,
		`\.\.\\\.\.\/`,

		// === LONG PATH NAMES (Windows) ===
		`\\\\?\\.*\\\.\.`,
		`\\\\?\\UNC\\`,

		// === CASE VARIATIONS (Windows) ===
		`(?i)\.\.\\WiNdOwS`,
		`(?i)\.\.\\SyStEm32`,
	}

	compiled := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		compiled[i] = regexp.MustCompile(p)
	}

	return &PathTraversalDetector{patterns: compiled}
}

// Detect checks if input contains Path Traversal patterns
func (d *PathTraversalDetector) Detect(input string) (bool, string) {
	// Quick check for common indicators
	if !strings.Contains(input, "..") &&
		!strings.Contains(input, "%2e") &&
		!strings.Contains(input, "%252e") &&
		!strings.Contains(input, "\\") {
		return false, ""
	}

	// Check all patterns
	for _, pattern := range d.patterns {
		if pattern.MatchString(input) {
			return true, "Path Traversal attack detected: " + pattern.String()
		}
	}

	return false, ""
}
