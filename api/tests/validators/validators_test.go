// tests/validators/validators_test.go
package validators_test

import (
	"testing"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/validators"
	"github.com/stretchr/testify/assert"
)

// String Validators Tests

func TestIsEmpty(t *testing.T) {
	assert.True(t, validators.IsEmpty(""))
	assert.True(t, validators.IsEmpty("   "))
	assert.True(t, validators.IsEmpty("\t\n"))
	assert.False(t, validators.IsEmpty("a"))
	assert.False(t, validators.IsEmpty("  a  "))
}

func TestIsNotEmpty(t *testing.T) {
	assert.False(t, validators.IsNotEmpty(""))
	assert.False(t, validators.IsNotEmpty("   "))
	assert.False(t, validators.IsNotEmpty("\t\n"))
	assert.True(t, validators.IsNotEmpty("a"))
	assert.True(t, validators.IsNotEmpty("  a  "))
}

func TestRequireNotEmpty(t *testing.T) {
	// Test valid cases
	assert.NoError(t, validators.RequireNotEmpty("test", "field"))
	assert.NoError(t, validators.RequireNotEmpty("  test  ", "field"))
	assert.NoError(t, validators.RequireNotEmpty("a", "field"))

	// Test invalid cases
	assert.Error(t, validators.RequireNotEmpty("", "field"))
	assert.Error(t, validators.RequireNotEmpty("   ", "field"))
	assert.Error(t, validators.RequireNotEmpty("\t\n", "field"))
	assert.Contains(t, validators.RequireNotEmpty("", "field").Error(), "cannot be empty")
}

func TestMinLength(t *testing.T) {
	assert.True(t, validators.MinLength("test", 3))
	assert.True(t, validators.MinLength("test", 4))
	assert.True(t, validators.MinLength("  test  ", 4))
	assert.False(t, validators.MinLength("te", 3))
	assert.False(t, validators.MinLength("", 1))
	assert.True(t, validators.MinLength("   ", 0)) // Edge case: empty string with min length 0
}

func TestMaxLength(t *testing.T) {
	assert.True(t, validators.MaxLength("test", 5))
	assert.True(t, validators.MaxLength("test", 4))
	assert.True(t, validators.MaxLength("  test  ", 8))
	assert.False(t, validators.MaxLength("test", 3))
	assert.True(t, validators.MaxLength("", 5))
	assert.True(t, validators.MaxLength("   ", 3))
}

func TestRequireLength(t *testing.T) {
	// Test valid cases
	assert.NoError(t, validators.RequireLength("test", "field", 3, 5))
	assert.NoError(t, validators.RequireLength("test", "field", 4, 4))
	assert.NoError(t, validators.RequireLength("  test  ", "field", 4, 8))

	// Test too short
	err := validators.RequireLength("te", "field", 3, 5)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be at least")

	// Test too long
	err = validators.RequireLength("testing", "field", 3, 5)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot exceed")
}
// Multiple Values Tests

func TestIsAnyEmpty(t *testing.T) {
	assert.True(t, validators.IsAnyEmpty("", "test", "another"))
	assert.True(t, validators.IsAnyEmpty("test", "", "another"))
	assert.True(t, validators.IsAnyEmpty("test", "another", ""))
	assert.True(t, validators.IsAnyEmpty("   ", "test"))
	assert.False(t, validators.IsAnyEmpty("test", "another"))
	assert.False(t, validators.IsAnyEmpty("test"))
	assert.False(t, validators.IsAnyEmpty()) // Edge case: no arguments
}

func TestIsAllEmpty(t *testing.T) {
	assert.True(t, validators.IsAllEmpty("", "", ""))
	assert.True(t, validators.IsAllEmpty("   ", "\t\n"))
	assert.True(t, validators.IsAllEmpty()) // Edge case: no arguments
	assert.False(t, validators.IsAllEmpty("", "test", ""))
	assert.False(t, validators.IsAllEmpty("test", ""))
	assert.False(t, validators.IsAllEmpty("test", "another"))
}

func TestRequireAllNotEmpty(t *testing.T) {
	// Test valid cases
	assert.NoError(t, validators.RequireAllNotEmpty(map[string]string{
		"field1": "value1",
		"field2": "value2",
		"field3": "value3",
	}))

	assert.NoError(t, validators.RequireAllNotEmpty(map[string]string{
		"field1": "  value1  ",
	}))

	// Test invalid cases
	err := validators.RequireAllNotEmpty(map[string]string{
		"field1": "value1",
		"field2": "",
		"field3": "value3",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "field2")

	err = validators.RequireAllNotEmpty(map[string]string{
		"field1": "   ",
		"field2": "value2",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "field1")

	// Edge case: empty map
	assert.NoError(t, validators.RequireAllNotEmpty(map[string]string{}))
}

// IP/Network Validators Tests

func TestIsValidIP(t *testing.T) {
	// Valid IPv4
	assert.True(t, validators.IsValidIP("192.168.1.1"))
	assert.True(t, validators.IsValidIP("127.0.0.1"))
	assert.True(t, validators.IsValidIP("0.0.0.0"))
	assert.True(t, validators.IsValidIP("255.255.255.255"))
	assert.True(t, validators.IsValidIP("  192.168.1.1  ")) // With spaces

	// Valid IPv6
	assert.True(t, validators.IsValidIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"))
	assert.True(t, validators.IsValidIP("::1"))
	assert.True(t, validators.IsValidIP("fe80::1"))

	// Invalid
	assert.False(t, validators.IsValidIP(""))
	assert.False(t, validators.IsValidIP("   "))
	assert.False(t, validators.IsValidIP("192.168.1.256"))
	assert.False(t, validators.IsValidIP("192.168.1"))
	assert.False(t, validators.IsValidIP("not-an-ip"))
}

func TestIsValidIPv4(t *testing.T) {
	// Valid IPv4
	assert.True(t, validators.IsValidIPv4("192.168.1.1"))
	assert.True(t, validators.IsValidIPv4("127.0.0.1"))
	assert.True(t, validators.IsValidIPv4("0.0.0.0"))
	assert.True(t, validators.IsValidIPv4("255.255.255.255"))

	// Invalid IPv4 (should be false even for valid IPv6)
	assert.False(t, validators.IsValidIPv4("2001:0db8:85a3:0000:0000:8a2e:0370:7334"))
	assert.False(t, validators.IsValidIPv4("::1"))
	assert.False(t, validators.IsValidIPv4("192.168.1.256"))
	assert.False(t, validators.IsValidIPv4(""))
}

func TestIsValidIPv6(t *testing.T) {
	// Valid IPv6
	assert.True(t, validators.IsValidIPv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334"))
	assert.True(t, validators.IsValidIPv6("::1"))
	assert.True(t, validators.IsValidIPv6("fe80::1"))

	// Invalid IPv6 (should be false even for valid IPv4)
	assert.False(t, validators.IsValidIPv6("192.168.1.1"))
	assert.False(t, validators.IsValidIPv6("127.0.0.1"))
	assert.False(t, validators.IsValidIPv6(""))
	assert.False(t, validators.IsValidIPv6("not-an-ip"))
}

func TestIsValidCIDR(t *testing.T) {
	// Valid CIDR
	assert.True(t, validators.IsValidCIDR("192.168.1.0/24"))
	assert.True(t, validators.IsValidCIDR("10.0.0.0/8"))
	assert.True(t, validators.IsValidCIDR("2001:db8::/32"))
	assert.True(t, validators.IsValidCIDR("  192.168.1.0/24  "))

	// Invalid CIDR
	assert.False(t, validators.IsValidCIDR(""))
	assert.False(t, validators.IsValidCIDR("192.168.1.1"))
	assert.False(t, validators.IsValidCIDR("192.168.1.0/33"))
	assert.False(t, validators.IsValidCIDR("not-a-cidr"))
}

func TestRequireValidIP(t *testing.T) {
	// Test valid cases
	assert.NoError(t, validators.RequireValidIP("192.168.1.1", "ip"))
	assert.NoError(t, validators.RequireValidIP("2001:db8::1", "ip"))
	assert.NoError(t, validators.RequireValidIP("  192.168.1.1  ", "ip"))

	// Test invalid cases
	err := validators.RequireValidIP("", "ip")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not a valid IP")

	err = validators.RequireValidIP("invalid", "ip")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not a valid IP")
}

// Email/URL Validators Tests

func TestIsValidEmail(t *testing.T) {
	// Valid emails
	assert.True(t, validators.IsValidEmail("test@example.com"))
	assert.True(t, validators.IsValidEmail("user.name@domain.co.uk"))
	assert.True(t, validators.IsValidEmail("user+tag@example.org"))
	assert.True(t, validators.IsValidEmail("test123@sub.domain.com"))
	assert.True(t, validators.IsValidEmail("  test@example.com  "))

	// Invalid emails
	assert.False(t, validators.IsValidEmail(""))
	assert.False(t, validators.IsValidEmail("   "))
	assert.False(t, validators.IsValidEmail("test@"))
	assert.False(t, validators.IsValidEmail("@example.com"))
	assert.False(t, validators.IsValidEmail("test@.com"))
	assert.False(t, validators.IsValidEmail("test@com"))
	assert.False(t, validators.IsValidEmail("test example.com"))
}

func TestRequireValidEmail(t *testing.T) {
	// Test valid cases
	assert.NoError(t, validators.RequireValidEmail("test@example.com", "email"))
	assert.NoError(t, validators.RequireValidEmail("  test@example.com  ", "email"))

	// Test invalid cases
	err := validators.RequireValidEmail("", "email")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not a valid email")

	err = validators.RequireValidEmail("invalid", "email")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not a valid email")
}

func TestIsValidURL(t *testing.T) {
	// Valid URLs
	assert.True(t, validators.IsValidURL("http://example.com"))
	assert.True(t, validators.IsValidURL("https://example.com"))
	assert.True(t, validators.IsValidURL("http://sub.example.com/path"))
	assert.True(t, validators.IsValidURL("  http://example.com  "))
	assert.True(t, validators.IsValidURL("https://example.com:8080/path?query=value"))

	// Invalid URLs
	assert.False(t, validators.IsValidURL(""))
	assert.False(t, validators.IsValidURL("   "))
	assert.False(t, validators.IsValidURL("example.com"))
	assert.False(t, validators.IsValidURL("ftp://example.com"))
	assert.False(t, validators.IsValidURL("://example.com"))
}

// Numeric Validators Tests

func TestIsValidPort(t *testing.T) {
	// Valid ports
	assert.True(t, validators.IsValidPort(1))
	assert.True(t, validators.IsValidPort(80))
	assert.True(t, validators.IsValidPort(443))
	assert.True(t, validators.IsValidPort(65535))

	// Invalid ports
	assert.False(t, validators.IsValidPort(0))
	assert.False(t, validators.IsValidPort(-1))
	assert.False(t, validators.IsValidPort(65536))
	assert.False(t, validators.IsValidPort(70000))
}

func TestRequireValidPort(t *testing.T) {
	// Test valid cases
	assert.NoError(t, validators.RequireValidPort(80, "port"))
	assert.NoError(t, validators.RequireValidPort(1, "port"))
	assert.NoError(t, validators.RequireValidPort(65535, "port"))

	// Test invalid cases
	err := validators.RequireValidPort(0, "port")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be between")

	err = validators.RequireValidPort(65536, "port")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be between")
}

func TestIsInRange(t *testing.T) {
	assert.True(t, validators.IsInRange(5, 1, 10))
	assert.True(t, validators.IsInRange(1, 1, 10))
	assert.True(t, validators.IsInRange(10, 1, 10))
	assert.True(t, validators.IsInRange(0, 0, 0))

	assert.False(t, validators.IsInRange(0, 1, 10))
	assert.False(t, validators.IsInRange(11, 1, 10))
	assert.False(t, validators.IsInRange(-1, 0, 5))
}

func TestRequireInRange(t *testing.T) {
	// Test valid cases
	assert.NoError(t, validators.RequireInRange(5, 1, 10, "value"))
	assert.NoError(t, validators.RequireInRange(1, 1, 10, "value"))
	assert.NoError(t, validators.RequireInRange(10, 1, 10, "value"))

	// Test invalid cases (too low)
	err := validators.RequireInRange(0, 1, 10, "value")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be between")

	// Test invalid cases (too high)
	err = validators.RequireInRange(11, 1, 10, "value")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be between")
}

// Time Validators Tests

func TestIsValidDuration(t *testing.T) {
	assert.True(t, validators.IsValidDuration(time.Second))
	assert.True(t, validators.IsValidDuration(time.Minute))
	assert.True(t, validators.IsValidDuration(time.Hour))
	assert.True(t, validators.IsValidDuration(1 * time.Nanosecond))

	assert.False(t, validators.IsValidDuration(0))
	assert.False(t, validators.IsValidDuration(-time.Second))
	assert.False(t, validators.IsValidDuration(-time.Hour))
}

func TestRequireValidDuration(t *testing.T) {
	// Test valid cases
	assert.NoError(t, validators.RequireValidDuration(time.Second, "duration"))
	assert.NoError(t, validators.RequireValidDuration(time.Hour, "duration"))
	assert.NoError(t, validators.RequireValidDuration(1*time.Millisecond, "duration"))

	// Test invalid cases
	err := validators.RequireValidDuration(0, "duration")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be positive")

	err = validators.RequireValidDuration(-time.Second, "duration")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be positive")
}

func TestIsInFuture(t *testing.T) {
	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Hour)

	assert.True(t, validators.IsInFuture(future))
	assert.False(t, validators.IsInFuture(past))
}

func TestIsInPast(t *testing.T) {
	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Hour)

	assert.True(t, validators.IsInPast(past))
	assert.False(t, validators.IsInPast(future))
}

// Enum/Choice Validators Tests

func TestIsValidChoice(t *testing.T) {
	choices := []string{"option1", "option2", "option3"}

	// Valid choices
	assert.True(t, validators.IsValidChoice("option1", choices))
	assert.True(t, validators.IsValidChoice("option2", choices))
	assert.True(t, validators.IsValidChoice("option3", choices))

	// Invalid choices
	assert.False(t, validators.IsValidChoice("", choices))
	assert.False(t, validators.IsValidChoice("option4", choices))
	assert.False(t, validators.IsValidChoice("Option1", choices)) // case sensitive
	assert.False(t, validators.IsValidChoice("option", choices))

	// Edge cases
	assert.False(t, validators.IsValidChoice("test", []string{}))
	assert.False(t, validators.IsValidChoice("", []string{}))
}

func TestRequireValidChoice(t *testing.T) {
	choices := []string{"option1", "option2", "option3"}

	// Test valid cases
	assert.NoError(t, validators.RequireValidChoice("option1", choices, "choice"))
	assert.NoError(t, validators.RequireValidChoice("option2", choices, "choice"))
	assert.NoError(t, validators.RequireValidChoice("option3", choices, "choice"))

	// Test invalid cases
	err := validators.RequireValidChoice("option4", choices, "choice")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be one of")

	err = validators.RequireValidChoice("", choices, "choice")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be one of")
}

// Pattern Validators Tests

func TestMatchesPattern(t *testing.T) {
	// Valid patterns
	assert.True(t, validators.MatchesPattern("test123", `^[a-z0-9]+$`))
	assert.True(t, validators.MatchesPattern("12345", `^[0-9]+$`))
	assert.True(t, validators.MatchesPattern("abc", `^[a-z]{3}$`))
	assert.True(t, validators.MatchesPattern("", `^$`))

	// Invalid patterns
	assert.False(t, validators.MatchesPattern("test123", `^[a-z]+$`)) // contains numbers
	assert.False(t, validators.MatchesPattern("123abc", `^[0-9]+$`)) // contains letters
	assert.False(t, validators.MatchesPattern("ab", `^[a-z]{3}$`))   // wrong length

	// Invalid regex pattern (should return false, not panic)
	assert.False(t, validators.MatchesPattern("test", `[invalid(regex`))
}

func TestRequireMatchesPattern(t *testing.T) {
	pattern := `^[a-z0-9_]+$`

	// Test valid cases
	assert.NoError(t, validators.RequireMatchesPattern("test123", pattern, "field"))
	assert.NoError(t, validators.RequireMatchesPattern("user_name", pattern, "field"))
	assert.NoError(t, validators.RequireMatchesPattern("abc123", pattern, "field"))

	// Test invalid cases
	err := validators.RequireMatchesPattern("Test123", pattern, "field") // uppercase
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "format is invalid")

	err = validators.RequireMatchesPattern("test-123", pattern, "field") // hyphen
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "format is invalid")

	// Test with invalid regex pattern
	err = validators.RequireMatchesPattern("test", `[invalid(regex`, "field")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "format is invalid")
}

// Alpha/Numeric Validators Tests

func TestIsAlphanumeric(t *testing.T) {
	// Valid
	assert.True(t, validators.IsAlphanumeric("abc123"))
	assert.True(t, validators.IsAlphanumeric("ABC123"))
	assert.True(t, validators.IsAlphanumeric("123"))
	assert.True(t, validators.IsAlphanumeric("abc"))

	// Invalid
	assert.False(t, validators.IsAlphanumeric(""))
	assert.False(t, validators.IsAlphanumeric("abc 123"))
	assert.False(t, validators.IsAlphanumeric("abc-123"))
	assert.False(t, validators.IsAlphanumeric("abc_123"))
	assert.False(t, validators.IsAlphanumeric("abc.123"))
}

func TestIsAlpha(t *testing.T) {
	// Valid
	assert.True(t, validators.IsAlpha("abc"))
	assert.True(t, validators.IsAlpha("ABC"))
	assert.True(t, validators.IsAlpha("AbCd"))

	// Invalid
	assert.False(t, validators.IsAlpha(""))
	assert.False(t, validators.IsAlpha("abc123"))
	assert.False(t, validators.IsAlpha("123"))
	assert.False(t, validators.IsAlpha("abc def"))
	assert.False(t, validators.IsAlpha("abc-def"))
}

func TestIsNumeric(t *testing.T) {
	// Valid
	assert.True(t, validators.IsNumeric("123"))
	assert.True(t, validators.IsNumeric("0"))
	assert.True(t, validators.IsNumeric("1234567890"))

	// Invalid
	assert.False(t, validators.IsNumeric(""))
	assert.False(t, validators.IsNumeric("123abc"))
	assert.False(t, validators.IsNumeric("abc"))
	assert.False(t, validators.IsNumeric("12.34"))
	assert.False(t, validators.IsNumeric("12,34"))
}

func TestIsSlugFormat(t *testing.T) {
	// Valid
	assert.True(t, validators.IsSlugFormat("test-slug"))
	assert.True(t, validators.IsSlugFormat("test_slug"))
	assert.True(t, validators.IsSlugFormat("test123"))
	assert.True(t, validators.IsSlugFormat("test-123_slug"))
	assert.True(t, validators.IsSlugFormat("a-b-c"))

	// Invalid
	assert.False(t, validators.IsSlugFormat(""))
	assert.False(t, validators.IsSlugFormat("Test-Slug")) // uppercase
	assert.False(t, validators.IsSlugFormat("test.slug")) // dot
	assert.False(t, validators.IsSlugFormat("test slug")) // space
	assert.False(t, validators.IsSlugFormat("test@slug")) // @ symbol
}

// Batch Validators Tests

func TestValidateRequired(t *testing.T) {
	// Test with all fields present
	errors := validators.ValidateRequired(map[string]string{
		"field1": "value1",
		"field2": "value2",
		"field3": "value3",
	})
	assert.Empty(t, errors)

	// Test with empty fields
	errors = validators.ValidateRequired(map[string]string{
		"field1": "value1",
		"field2": "",
		"field3": "   ",
		"field4": "value4",
	})
	assert.Len(t, errors, 2)
	assert.Contains(t, errors[0].Error(), "field2")
	assert.Contains(t, errors[1].Error(), "field3")

	// Test with all empty fields
	errors = validators.ValidateRequired(map[string]string{
		"field1": "",
		"field2": "   ",
	})
	assert.Len(t, errors, 2)

	// Test empty map
	errors = validators.ValidateRequired(map[string]string{})
	assert.Empty(t, errors)
}

func TestValidateFieldLengths(t *testing.T) {
	// This is a placeholder function, so we just test it doesn't panic
	errors := validators.ValidateFieldLengths(map[string]int{
		"field1": 10,
		"field2": 20,
	})
	assert.Empty(t, errors)

	// Test with empty map
	errors = validators.ValidateFieldLengths(map[string]int{})
	assert.Empty(t, errors)
}

// Edge Cases and Additional Tests

func TestComplexScenarios(t *testing.T) {
	// Test combination of validators
	assert.True(t, validators.IsNotEmpty("test") && validators.MinLength("test", 3))
	assert.True(t, validators.IsValidEmail("test@example.com") && validators.MinLength("test@example.com", 10))
	assert.True(t, validators.IsValidIP("192.168.1.1") && validators.IsValidIPv4("192.168.1.1"))

	// Test error messages format
	err := validators.RequireNotEmpty("", "Username")
	assert.Equal(t, "Username cannot be empty", err.Error())

	err = validators.RequireValidIP("invalid", "IP Address")
	assert.Equal(t, "IP Address is not a valid IP address", err.Error())

	err = validators.RequireValidEmail("not-an-email", "Email")
	assert.Equal(t, "Email is not a valid email address", err.Error())
}

func TestTrimmingBehavior(t *testing.T) {
	// All validators should trim spaces
	assert.True(t, validators.IsEmpty("   "))
	assert.False(t, validators.IsNotEmpty("   "))
	assert.True(t, validators.MinLength("  a  ", 1))
	assert.True(t, validators.MaxLength("  a  ", 1))
	assert.True(t, validators.IsValidIP("  192.168.1.1  "))
	assert.True(t, validators.IsValidEmail("  test@example.com  "))
}

// Performance and Concurrency Tests (optional for coverage)

func TestConcurrentValidation(t *testing.T) {
	done := make(chan bool)
	
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				// Test various validators concurrently
				validators.IsValidEmail("test@example.com")
				validators.IsValidIP("192.168.1.1")
				validators.IsNotEmpty("test")
				validators.MinLength("test", 3)
				validators.RequireValidPort(80, "port")
				validators.IsInRange(5, 1, 10)
			}
			done <- true
		}(i)
	}
	
	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

// Test Type Assertions and Interface Compliance

func TestInterfaceCompliance(t *testing.T) {
	// Test that functions accept the expected types
	// This is mostly for compile-time checking
	
	// String validators
	_ = validators.IsEmpty("string")
	_ = validators.MinLength("string", 3)
	
	// Numeric validators
	_ = validators.IsValidPort(8080)
	_ = validators.IsInRange(5, 1, 10)
	
	// Time validators
	_ = validators.IsValidDuration(time.Second)
	_ = validators.IsInFuture(time.Now().Add(time.Hour))
	
	// Nil validators
	var ptr *string
	_ = validators.IsNil(ptr)
	_ = validators.IsNil([]string{})
	_ = validators.IsNil(map[string]string{})
	_ = validators.IsNil(interface{}(nil))
	_ = validators.IsNil("not nil")
	
	// This should compile without errors
	assert.True(t, true)
}


func TestDebugIsNilImplementation(t *testing.T) {
	// Test diagnostico per capire l'implementazione attuale
	
	// 1. Nil pointer
	var ptr *string
	t.Logf("IsNil(nil pointer): %v", validators.IsNil(ptr))
	
	// 2. Nil slice (dichiarata ma non inizializzata)
	var nilSlice []string
	t.Logf("IsNil(nil slice): %v", validators.IsNil(nilSlice))
	
	// 3. Empty slice (inizializzata ma vuota)
	emptySlice := []string{}
	t.Logf("IsNil(empty slice): %v", validators.IsNil(emptySlice))
	
	// 4. Nil map
	var nilMap map[string]string
	t.Logf("IsNil(nil map): %v", validators.IsNil(nilMap))
	
	// 5. Empty map
	emptyMap := map[string]string{}
	t.Logf("IsNil(empty map): %v", validators.IsNil(emptyMap))
	
	// 6. Nil interface
	var nilInterface interface{}
	t.Logf("IsNil(nil interface): %v", validators.IsNil(nilInterface))
	
	// 7. Interface with nil value
	var nilPtr *string
	var ifaceWithNil interface{} = nilPtr
	t.Logf("IsNil(interface with nil ptr): %v", validators.IsNil(ifaceWithNil))
	
	// 8. Direct nil
	t.Logf("IsNil(nil): %v", validators.IsNil(nil))
	
	// 9. String value
	t.Logf("IsNil('test'): %v", validators.IsNil("test"))
}