package helpers

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// ValidateRuleName validates a rule name
func ValidateRuleName(name string) error {
	if err := ValidateNonEmpty(name, "Rule name"); err != nil {
		return err
	}
	if len(name) > 255 {
		return fmt.Errorf("rule name cannot exceed 255 characters")
	}
	return nil
}

// ValidatePattern validates a rule pattern (regex)
func ValidatePattern(pattern string) error {
	if err := ValidateNonEmpty(pattern, "Pattern"); err != nil {
		return err
	}
	if len(pattern) > 2000 {
		return fmt.Errorf("pattern cannot exceed 2000 characters")
	}
	// Try to compile as regex to validate it's valid
	_, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid regex pattern: %v", err)
	}
	return nil
}

// ValidateSeverity validates a threat severity level
func ValidateSeverity(severity string) error {
	validSeverities := map[string]bool{
		"low":      true,
		"medium":   true,
		"high":     true,
		"critical": true,
	}
	if !validSeverities[strings.ToLower(severity)] {
		return fmt.Errorf("invalid severity level. Must be: low, medium, high, or critical")
	}
	return nil
}

// ValidateRuleAction validates a rule action type
func ValidateRuleAction(action string) error {
	validActions := map[string]bool{
		"log":       true,
		"detect":    true,
		"block":     true,
		"challenge": true,
		"drop":      true,
		"redirect":  true,
	}
	if !validActions[strings.ToLower(action)] {
		return fmt.Errorf("invalid action. Must be: log, detect, block, challenge, drop, or redirect")
	}
	return nil
}

// ValidateFalsePositiveStatus validates false positive status
func ValidateFalsePositiveStatus(status string) error {
	validStatuses := map[string]bool{
		"pending":    true,
		"reviewed":   true,
		"whitelisted": true,
	}
	if !validStatuses[strings.ToLower(status)] {
		return fmt.Errorf("invalid status. Must be: pending, reviewed, or whitelisted")
	}
	return nil
}

// ValidateURL validates a URL string (supports full URLs and relative paths)
func ValidateURL(url string) error {
	if url == "" {
		return nil // URL is optional
	}
	if len(url) > 2000 {
		return fmt.Errorf("URL cannot exceed 2000 characters")
	}
	// Accept both full URLs (http://...) and relative paths (/path?query)
	// Full URL pattern: http[s]://...
	fullURLPattern := regexp.MustCompile(`^https?://[a-zA-Z0-9\-._~:/?#@!$&'()*+,;=]+$`)
	// Relative path pattern: /path or path or /path?query=...
	relativePath := regexp.MustCompile(`^/?[a-zA-Z0-9\-._~/?#@!$&'()*+,;=]+$`)

	if !fullURLPattern.MatchString(url) && !relativePath.MatchString(url) {
		return fmt.Errorf("invalid URL format")
	}
	return nil
}

// ValidateUserAgent validates a user agent string
func ValidateUserAgent(ua string) error {
	if ua == "" {
		return nil // User agent is optional
	}
	if len(ua) > 500 {
		return fmt.Errorf("user agent cannot exceed 500 characters")
	}
	return nil
}

// ValidateDescription validates a description string
func ValidateDescription(desc string) error {
	if desc == "" {
		return nil // Description is optional
	}
	if len(desc) > 500 {
		return fmt.Errorf("description cannot exceed 500 characters")
	}
	return nil
}

// ValidatePayload validates a payload/body content
func ValidatePayload(payload string) error {
	if payload == "" {
		return nil // Payload is optional
	}
	if len(payload) > 10000 {
		return fmt.Errorf("payload cannot exceed 10000 characters")
	}
	return nil
}

// ValidateNonEmpty validates that a string is not empty
func ValidateNonEmpty(value string, fieldName string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s cannot be empty", fieldName)
	}
	return nil
}

// ValidateStringLength validates a string length
func ValidateStringLength(value string, fieldName string, minLen, maxLen int) error {
	length := len(strings.TrimSpace(value))
	if length < minLen {
		return fmt.Errorf("%s must be at least %d characters", fieldName, minLen)
	}
	if length > maxLen {
		return fmt.Errorf("%s cannot exceed %d characters", fieldName, maxLen)
	}
	return nil
}

// ValidateHTTPMethod validates HTTP method
func ValidateHTTPMethod(method string) error {
	if method == "" {
		return nil // Method is optional
	}
	validMethods := map[string]bool{
		"GET":     true,
		"POST":    true,
		"PUT":     true,
		"DELETE":  true,
		"PATCH":   true,
		"HEAD":    true,
		"OPTIONS": true,
		"TRACE":   true,
		"CONNECT": true,
	}
	if !validMethods[strings.ToUpper(method)] {
		return fmt.Errorf("invalid HTTP method: %s", method)
	}
	return nil
}

// ValidateReviewNotes validates review notes for false positives
func ValidateReviewNotes(notes string) error {
	if notes == "" {
		return nil // Notes are optional
	}
	if len(notes) > 1000 {
		return fmt.Errorf("review notes cannot exceed 1000 characters")
	}
	return nil
}

// ValidateIPAddress validates an IP address (without blocking checks)
func ValidateIPAddress(ip string) error {
	if ip == "" {
		return fmt.Errorf("IP address cannot be empty")
	}

	// Use net.ParseIP for proper IP validation (supports both IPv4 and IPv6)
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address format")
	}

	return nil
}
