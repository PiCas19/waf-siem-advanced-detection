package validators

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// String Validators

// IsEmpty checks if a string is empty or contains only whitespace
func IsEmpty(s string) bool {
	return strings.TrimSpace(s) == ""
}

// IsNotEmpty checks if a string is not empty
func IsNotEmpty(s string) bool {
	return !IsEmpty(s)
}

// RequireNotEmpty returns an error if string is empty
func RequireNotEmpty(s, fieldName string) error {
	if IsEmpty(s) {
		return fmt.Errorf("%s cannot be empty", fieldName)
	}
	return nil
}

// MinLength checks if string has minimum length
func MinLength(s string, min int) bool {
	return len(strings.TrimSpace(s)) >= min
}

// MaxLength checks if string has maximum length
func MaxLength(s string, max int) bool {
	return len(strings.TrimSpace(s)) <= max
}

// RequireLength checks if string length is within bounds
func RequireLength(s, fieldName string, min, max int) error {
	trimmed := strings.TrimSpace(s)
	if len(trimmed) < min {
		return fmt.Errorf("%s must be at least %d characters", fieldName, min)
	}
	if len(trimmed) > max {
		return fmt.Errorf("%s cannot exceed %d characters", fieldName, max)
	}
	return nil
}

// Nil/Pointer Validators

// IsNil checks if a pointer is nil
func IsNil(v interface{}) bool {
	return v == nil
}

// IsNotNil checks if a pointer is not nil
func IsNotNil(v interface{}) bool {
	return v != nil
}

// RequireNotNil returns an error if value is nil
func RequireNotNil(v interface{}, fieldName string) error {
	if IsNil(v) {
		return fmt.Errorf("%s cannot be nil", fieldName)
	}
	return nil
}

// Multiple Values

// IsAnyEmpty checks if any string is empty
func IsAnyEmpty(values ...string) bool {
	for _, v := range values {
		if IsEmpty(v) {
			return true
		}
	}
	return false
}

// IsAllEmpty checks if all strings are empty
func IsAllEmpty(values ...string) bool {
	for _, v := range values {
		if IsNotEmpty(v) {
			return false
		}
	}
	return true
}

// RequireAllNotEmpty returns error if any string is empty
func RequireAllNotEmpty(fields map[string]string) error {
	for name, value := range fields {
		if IsEmpty(value) {
			return fmt.Errorf("%s cannot be empty", name)
		}
	}
	return nil
}

// IP/Network Validators

// IsValidIP checks if string is a valid IPv4 or IPv6 address
func IsValidIP(ip string) bool {
	return net.ParseIP(strings.TrimSpace(ip)) != nil
}

// IsValidIPv4 checks if string is a valid IPv4 address
func IsValidIPv4(ip string) bool {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	return parsed != nil && parsed.To4() != nil
}

// IsValidIPv6 checks if string is a valid IPv6 address
func IsValidIPv6(ip string) bool {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	return parsed != nil && parsed.To4() == nil
}

// IsValidCIDR checks if string is a valid CIDR notation
func IsValidCIDR(cidr string) bool {
	_, _, err := net.ParseCIDR(strings.TrimSpace(cidr))
	return err == nil
}

// RequireValidIP returns error if IP is invalid
func RequireValidIP(ip, fieldName string) error {
	if !IsValidIP(ip) {
		return fmt.Errorf("%s is not a valid IP address", fieldName)
	}
	return nil
}

// Email/URL Validators

// IsValidEmail checks if string is a valid email format
func IsValidEmail(email string) bool {
	pattern := `^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`
	regex := regexp.MustCompile(pattern)
	return regex.MatchString(strings.TrimSpace(email))
}

// RequireValidEmail returns error if email is invalid
func RequireValidEmail(email, fieldName string) error {
	if !IsValidEmail(email) {
		return fmt.Errorf("%s is not a valid email address", fieldName)
	}
	return nil
}

// IsValidURL checks if string is a valid URL
func IsValidURL(url string) bool {
	pattern := `^https?://`
	regex := regexp.MustCompile(pattern)
	return regex.MatchString(strings.TrimSpace(url))
}

// Numeric Validators

// IsValidPort checks if number is a valid port (1-65535)
func IsValidPort(port int) bool {
	return port > 0 && port <= 65535
}

// RequireValidPort returns error if port is invalid
func RequireValidPort(port int, fieldName string) error {
	if !IsValidPort(port) {
		return fmt.Errorf("%s must be between 1 and 65535", fieldName)
	}
	return nil
}

// IsInRange checks if number is within range
func IsInRange(value, min, max int) bool {
	return value >= min && value <= max
}

// RequireInRange returns error if value is outside range
func RequireInRange(value, min, max int, fieldName string) error {
	if !IsInRange(value, min, max) {
		return fmt.Errorf("%s must be between %d and %d", fieldName, min, max)
	}
	return nil
}

// Time Validators

// IsValidDuration checks if duration is positive
func IsValidDuration(d time.Duration) bool {
	return d > 0
}

// RequireValidDuration returns error if duration is invalid
func RequireValidDuration(d time.Duration, fieldName string) error {
	if !IsValidDuration(d) {
		return fmt.Errorf("%s must be positive", fieldName)
	}
	return nil
}

// IsInFuture checks if time is in the future
func IsInFuture(t time.Time) bool {
	return t.After(time.Now())
}

// IsInPast checks if time is in the past
func IsInPast(t time.Time) bool {
	return t.Before(time.Now())
}

// Enum/Choice Validators

// IsValidChoice checks if value is in allowed choices
func IsValidChoice(value string, choices []string) bool {
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}

// RequireValidChoice returns error if value is not in choices
func RequireValidChoice(value string, choices []string, fieldName string) error {
	if !IsValidChoice(value, choices) {
		return fmt.Errorf("%s must be one of: %v", fieldName, choices)
	}
	return nil
}

// Pattern Validators

// MatchesPattern checks if string matches regex pattern
func MatchesPattern(s, pattern string) bool {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return regex.MatchString(s)
}

// RequireMatchesPattern returns error if string doesn't match pattern
func RequireMatchesPattern(s, pattern, fieldName string) error {
	if !MatchesPattern(s, pattern) {
		return fmt.Errorf("%s format is invalid", fieldName)
	}
	return nil
}

// Alpha/Numeric Validators

// IsAlphanumeric checks if string contains only alphanumeric characters
func IsAlphanumeric(s string) bool {
	pattern := `^[a-zA-Z0-9]+$`
	return MatchesPattern(s, pattern)
}

// IsAlpha checks if string contains only letters
func IsAlpha(s string) bool {
	pattern := `^[a-zA-Z]+$`
	return MatchesPattern(s, pattern)
}

// IsNumeric checks if string contains only digits
func IsNumeric(s string) bool {
	pattern := `^[0-9]+$`
	return MatchesPattern(s, pattern)
}

// IsSlugFormat checks if string is valid URL slug (lowercase, hyphens, underscores)
func IsSlugFormat(s string) bool {
	pattern := `^[a-z0-9\-_]+$`
	return MatchesPattern(s, pattern)
}

// Batch Validators

// ValidateRequired returns errors for all empty required fields
func ValidateRequired(fields map[string]string) []error {
	var errors []error
	for name, value := range fields {
		if IsEmpty(value) {
			errors = append(errors, fmt.Errorf("%s is required", name))
		}
	}
	return errors
}

// ValidateFieldLengths returns errors for fields exceeding max length
// Note: actual field values would need to be passed separately
// This is a template for batch validation
func ValidateFieldLengths(fields map[string]int) []error {
	var errors []error
	// Placeholder implementation for future use
	_ = fields
	return errors
}
