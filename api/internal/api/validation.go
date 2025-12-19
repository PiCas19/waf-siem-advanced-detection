package api

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// ValidateIP valida che l'input sia un IP valido (IPv4 o IPv6)
// Ritorna l'IP normalizzato e un errore se non valido
func ValidateIP(input string) (string, error) {
	if input == "" {
		return "", fmt.Errorf("IP address cannot be empty")
	}

	// Trim whitespace
	ip := strings.TrimSpace(input)

	// Prova a parsare come IP
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return "", fmt.Errorf("invalid IP address format: %s", ip)
	}

	// Reject loopback IPs (127.0.0.1, ::1, etc)
	if parsedIP.IsLoopback() {
		return "", fmt.Errorf("cannot block/whitelist loopback IP: %s", ip)
	}

	return parsedIP.String(), nil
}

// ValidateReason valida la reason string
// Deve essere non-vuota, < 500 chars, senza caratteri pericolosi
func ValidateReason(reason string) error {
	trimmed := strings.TrimSpace(reason)
	if trimmed == "" {
		return fmt.Errorf("reason cannot be empty")
	}

	if len(reason) > 500 {
		return fmt.Errorf("reason is too long (max 500 characters)")
	}

	// Check for potentially dangerous characters (basic check)
	// Solo allow alphanumeric, spaces, and basic punctuation
	validPattern := regexp.MustCompile(`^[a-zA-Z0-9\s\-_.(),;:'"\/\[\]]+$`)
	if !validPattern.MatchString(trimmed) {
		return fmt.Errorf("reason contains invalid characters")
	}

	return nil
}

// ValidateThreat valida la threat/description string
// Deve essere non-vuota, < 255 chars
func ValidateThreat(threat string) error {
	trimmed := strings.TrimSpace(threat)
	if trimmed == "" {
		return fmt.Errorf("threat type cannot be empty")
	}

	if len(threat) > 255 {
		return fmt.Errorf("threat type is too long (max 255 characters)")
	}

	// Deve essere un valore noto o custom rule name
	validPattern := regexp.MustCompile(`^[a-zA-Z0-9\-_\s]+$`)
	if !validPattern.MatchString(trimmed) {
		return fmt.Errorf("threat type contains invalid characters")
	}

	return nil
}

// ValidateDuration valida la durata del blocco
func ValidateDuration(durationHours int) error {
	if durationHours == -1 {
		// -1 significa permanent, è ok
		return nil
	}

	if durationHours == 0 {
		// 0 significa usa il default (24 hours), è ok
		return nil
	}

	if durationHours < 0 {
		return fmt.Errorf("duration must be positive, 0 for default, or -1 for permanent")
	}

	// Max 10 years
	if durationHours > 87600 {
		return fmt.Errorf("duration cannot exceed 10 years (87600 hours)")
	}

	return nil
}

// ValidateEmail valida che l'input sia un email valido
func ValidateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("email cannot be empty")
	}

	trimmed := strings.TrimSpace(email)
	if len(trimmed) > 254 {
		return fmt.Errorf("email is too long (max 254 characters)")
	}

	// Basic email pattern: localpart@domain.extension
	emailPattern := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	if !emailPattern.MatchString(trimmed) {
		return fmt.Errorf("invalid email format")
	}

	return nil
}

// ValidateNonEmptyString valida che una stringa non sia vuota
func ValidateNonEmptyString(value string, fieldName string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s cannot be empty", fieldName)
	}
	return nil
}

// ValidateStringLength valida la lunghezza di una stringa
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
