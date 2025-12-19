package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	internalapi "github.com/PiCas19/waf-siem-advanced-detection/api/internal/api"
)

// TestValidateIP tests the ValidateIP function with all error messages
func TestValidateIP(t *testing.T) {
	// Test empty IP
	ip, err := internalapi.ValidateIP("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "IP address cannot be empty")
	assert.Empty(t, ip)

	// Test invalid IP format
	ip, err = internalapi.ValidateIP("invalid-ip")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid IP address format")
	assert.Empty(t, ip)

	// Test loopback IP (should error based on your code)
	ip, err = internalapi.ValidateIP("127.0.0.1")
	assert.Error(t, err)
	assert.Empty(t, ip)

	// Test valid IP
	ip, err = internalapi.ValidateIP("8.8.8.8")
	assert.NoError(t, err)
	assert.Equal(t, "8.8.8.8", ip)

	// Test another invalid format
	ip, err = internalapi.ValidateIP("256.256.256.256")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid IP address format")
	assert.Empty(t, ip)
}

// TestValidateReason tests the ValidateReason function with all error messages
func TestValidateReason(t *testing.T) {
	// Test empty reason
	err := internalapi.ValidateReason("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "reason cannot be empty")

	// Test reason with only spaces
	err = internalapi.ValidateReason("   ")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "reason cannot be empty")

	// Test reason too long
	longReason := ""
	for i := 0; i < 501; i++ {
		longReason += "a"
	}
	err = internalapi.ValidateReason(longReason)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "reason is too long (max 500 characters)")

	// Test reason with invalid characters
	err = internalapi.ValidateReason("Reason with @ invalid")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "reason contains invalid characters")

	err = internalapi.ValidateReason("<script>alert('xss')</script>")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "reason contains invalid characters")

	// Test valid reason
	err = internalapi.ValidateReason("Valid reason for blocking")
	assert.NoError(t, err)

	// Test reason with allowed punctuation
	err = internalapi.ValidateReason("Suspected attack - multiple attempts (5 times)")
	assert.NoError(t, err)
}

// TestValidateThreat tests the ValidateThreat function
func TestValidateThreat(t *testing.T) {
	// Test empty threat
	err := internalapi.ValidateThreat("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "threat type cannot be empty")

	// Test threat with only spaces
	err = internalapi.ValidateThreat("   ")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "threat type cannot be empty")

	// Test threat too long
	longThreat := ""
	for i := 0; i < 256; i++ {
		longThreat += "a"
	}
	err = internalapi.ValidateThreat(longThreat)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "threat type is too long (max 255 characters)")

	// Test threat with invalid characters
	err = internalapi.ValidateThreat("xss@attack")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "threat type contains invalid characters")

	// Test valid threats
	err = internalapi.ValidateThreat("XSS")
	assert.NoError(t, err)

	err = internalapi.ValidateThreat("SQL Injection")
	assert.NoError(t, err)

	err = internalapi.ValidateThreat("custom-rule-1")
	assert.NoError(t, err)
}

// TestValidateDuration tests the ValidateDuration function
func TestValidateDuration(t *testing.T) {
	// Test negative duration (except -1)
	err := internalapi.ValidateDuration(-2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "duration must be positive")

	// Test duration too long
	err = internalapi.ValidateDuration(87601)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "duration cannot exceed 10 years")

	// Test valid durations
	err = internalapi.ValidateDuration(-1)
	assert.NoError(t, err)

	err = internalapi.ValidateDuration(0)
	assert.NoError(t, err)

	err = internalapi.ValidateDuration(1)
	assert.NoError(t, err)

	err = internalapi.ValidateDuration(24)
	assert.NoError(t, err)

	err = internalapi.ValidateDuration(87600) // 10 years
	assert.NoError(t, err)
}

// TestValidateEmail tests the ValidateEmail function
func TestValidateEmail(t *testing.T) {
	// Test empty email
	err := internalapi.ValidateEmail("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "email cannot be empty")

	// Test email with only spaces
	err = internalapi.ValidateEmail("   ")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid email format")

	// Test email too long
	longEmail := ""
	for i := 0; i < 255; i++ {
		longEmail += "a"
	}
	err = internalapi.ValidateEmail(longEmail)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "email is too long")

	// Test invalid email format
	err = internalapi.ValidateEmail("invalid-email")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid email format")

	// Test valid emails
	err = internalapi.ValidateEmail("user@example.com")
	assert.NoError(t, err)

	err = internalapi.ValidateEmail("test.user+tag@subdomain.example.co.uk")
	assert.NoError(t, err)
}

// TestValidateNonEmptyString tests the ValidateNonEmptyString function
func TestValidateNonEmptyString(t *testing.T) {
	// Test empty string
	err := internalapi.ValidateNonEmptyString("", "fieldName")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "fieldName cannot be empty")

	// Test string with only spaces
	err = internalapi.ValidateNonEmptyString("   ", "fieldName")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "fieldName cannot be empty")

	// Test valid string
	err = internalapi.ValidateNonEmptyString("test", "field")
	assert.NoError(t, err)

	err = internalapi.ValidateNonEmptyString(" test ", "field")
	assert.NoError(t, err)
}

// TestValidateStringLength tests the ValidateStringLength function
func TestValidateStringLength(t *testing.T) {
	// Test string too short
	err := internalapi.ValidateStringLength("ab", "field", 3, 10)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "field must be at least 3 characters")

	// Test string too long
	err = internalapi.ValidateStringLength("abcdefghijk", "field", 3, 10)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "field cannot exceed 10 characters")

	// Test valid strings
	err = internalapi.ValidateStringLength("abc", "field", 3, 10)
	assert.NoError(t, err)

	err = internalapi.ValidateStringLength("abcdefghij", "field", 3, 10)
	assert.NoError(t, err)

	err = internalapi.ValidateStringLength(" test ", "field", 3, 10)
	assert.NoError(t, err)
}