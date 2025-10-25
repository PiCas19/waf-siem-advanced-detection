package detector

import (
	"regexp"
	"strings"
)

// ResponseSplittingDetector detects HTTP Response Splitting / CRLF Injection attacks
type ResponseSplittingDetector struct {
	patterns []*regexp.Regexp
}

// NewResponseSplittingDetector creates a new HTTP Response Splitting detector
func NewResponseSplittingDetector() *ResponseSplittingDetector {
	patterns := []string{
		// === CRLF INJECTION (Basic) ===
		`\r\n`,
		`\n`,
		`\r`,

		// === URL ENCODED CRLF ===
		`%0d%0a`,
		`%0D%0A`,
		`%0a`,
		`%0A`,
		`%0d`,
		`%0D`,

		// === DOUBLE URL ENCODED ===
		`%250d%250a`,
		`%250D%250A`,
		`%250a`,
		`%250A`,

		// === UNICODE ENCODED ===
		`%u000d%u000a`,
		`%u000D%u000A`,
		`\u000d\u000a`,
		`\u000D\u000A`,

		// === UTF-8 ENCODED ===
		`%c0%8d%c0%8a`,
		`%e5%98%8a%e5%98%8d`,

		// === HEADER INJECTION ===
		`\r\n.*:`,
		`%0d%0a.*:`,
		`\n.*:`,
		`%0a.*:`,

		// === SET-COOKIE INJECTION ===
		`(?i)\r\nSet-Cookie:`,
		`(?i)%0d%0aSet-Cookie:`,
		`(?i)\nSet-Cookie:`,
		`(?i)%0aSet-Cookie:`,

		// === LOCATION HEADER INJECTION ===
		`(?i)\r\nLocation:`,
		`(?i)%0d%0aLocation:`,
		`(?i)\nLocation:`,
		`(?i)%0aLocation:`,

		// === CONTENT-TYPE INJECTION ===
		`(?i)\r\nContent-Type:`,
		`(?i)%0d%0aContent-Type:`,

		// === RESPONSE SPLITTING (Double CRLF) ===
		`\r\n\r\n`,
		`%0d%0a%0d%0a`,
		`%0D%0A%0D%0A`,
		`\n\n`,
		`%0a%0a`,

		// === HTTP VERSION INJECTION ===
		`(?i)\r\nHTTP/`,
		`(?i)%0d%0aHTTP/`,
		`(?i)%0d%0aHTTP/1\\.`,

		// === STATUS CODE INJECTION ===
		`(?i)\r\nHTTP/1\\.[01]\s+[0-9]{3}`,
		`(?i)%0d%0aHTTP/1\\.[01]%20[0-9]{3}`,

		// === XSS VIA RESPONSE SPLITTING ===
		`\r\n\r\n<script`,
		`%0d%0a%0d%0a<script`,
		`%0d%0a%0d%0a.*javascript:`,

		// === CACHE POISONING ===
		`(?i)\r\nCache-Control:`,
		`(?i)%0d%0aCache-Control:`,
		`(?i)\r\nExpires:`,

		// === MULTIPLE HEADERS ===
		`\r\n.*:\r\n.*:`,
		`%0d%0a.*:%0d%0a.*:`,

		// === ALTERNATIVE LINE BREAKS ===
		`\x0d\x0a`,
		`\x0a`,
		`\x0d`,

		// === VERTICAL TAB / FORM FEED ===
		`\v`,
		`\f`,
		`%0b`,
		`%0c`,

		// === NULL BYTE WITH CRLF ===
		`%00\r\n`,
		`%00%0d%0a`,
		`\x00\r\n`,

		// === ENCODED VARIATIONS ===
		`\\r\\n`,
		`\\n`,
		`\\r`,
		`%5cr%5cn`,
		`%5Cr%5Cn`,

		// === MIXED ENCODING ===
		`%0d\n`,
		`\r%0a`,
		`%0d%0A`,
		`%0D%0a`,

		// === HEADER CONTINUATION ===
		`\r\n\s`,
		`%0d%0a\s`,
		`\n\s`,

		// === BROWSER-SPECIFIC ===
		`\r\n\t`,
		`%0d%0a%09`,

		// === JAVASCRIPT PROTOCOL IN HEADERS ===
		`\r\n.*javascript:`,
		`%0d%0a.*javascript:`,

		// === DATA URI IN HEADERS ===
		`\r\n.*data:`,
		`%0d%0a.*data:`,

		// === SESSION FIXATION VIA RESPONSE SPLITTING ===
		`\r\n.*sessionid=`,
		`%0d%0a.*sessionid=`,
		`\r\n.*PHPSESSID=`,

		// === CONTENT-LENGTH MANIPULATION ===
		`(?i)\r\nContent-Length:\s*0\r\n\r\n`,
		`(?i)%0d%0aContent-Length:%200%0d%0a%0d%0a`,

		// === TRANSFER-ENCODING SMUGGLING ===
		`(?i)\r\nTransfer-Encoding:`,
		`(?i)%0d%0aTransfer-Encoding:`,

		// === CHUNKED ENCODING ABUSE ===
		`(?i)\r\nTransfer-Encoding:\s*chunked`,

		// === HTTP REQUEST SMUGGLING ===
		`(?i)POST.*\r\n\r\n.*GET`,
		`(?i)GET.*\r\n\r\n.*POST`,

		// === HEADER NAME INJECTION ===
		`[^\x20-\x7E]\r\n`,
		`[^\x20-\x7E]%0d%0a`,
	}

	compiled := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		compiled[i] = regexp.MustCompile(p)
	}

	return &ResponseSplittingDetector{patterns: compiled}
}

// Detect checks if input contains Response Splitting patterns
func (d *ResponseSplittingDetector) Detect(input string) (bool, string) {
	// Check all patterns
	for _, pattern := range d.patterns {
		if pattern.MatchString(input) {
			return true, "HTTP Response Splitting/CRLF Injection attack detected: " + pattern.String()
		}
	}

	return false, ""
}
