package helpers_test

import (
	"fmt"
	"testing"
	"strings"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/helpers"
	"github.com/stretchr/testify/assert"
)

func TestValidateRuleName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected error
	}{
		{"Valid name", "Test Rule", nil},
		{"Empty name", "", fmt.Errorf("Rule name cannot be empty")},
		{"Only spaces", "   ", fmt.Errorf("Rule name cannot be empty")},
		{"Too long", string(make([]byte, 256)), fmt.Errorf("rule name cannot exceed 255 characters")},
		{"Exactly 255", string(make([]byte, 255)), nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := helpers.ValidateRuleName(tt.input)
			if tt.expected == nil {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tt.expected.Error())
			}
		})
	}
}

func TestValidatePattern(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected error
	}{
		{"Valid regex", "^test.*", nil},
		{"Empty pattern", "", fmt.Errorf("Pattern cannot be empty")},
		{"Only spaces", "   ", fmt.Errorf("Pattern cannot be empty")},
		{"Too long", string(make([]byte, 2001)), fmt.Errorf("pattern cannot exceed 2000 characters")},
		{"Exactly 2000", string(make([]byte, 2000)), nil},
		{"Invalid regex", "[invalid", fmt.Errorf("invalid regex pattern: error parsing regexp: missing closing ]: `[invalid`")},
		{"Complex valid regex", `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := helpers.ValidatePattern(tt.input)
			if tt.expected == nil {
				assert.NoError(t, err)
			} else {
				assert.Contains(t, err.Error(), tt.expected.Error())
			}
		})
	}
}

func TestValidateSeverity(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected error
	}{
		{"Valid low", "low", nil},
		{"Valid medium", "medium", nil},
		{"Valid high", "high", nil},
		{"Valid critical", "critical", nil},
		{"Case insensitive", "HIGH", nil},
		{"Mixed case", "MeDiUm", nil},
		{"Invalid", "unknown", fmt.Errorf("invalid severity level. Must be: low, medium, high, or critical")},
		{"Empty", "", fmt.Errorf("invalid severity level. Must be: low, medium, high, or critical")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := helpers.ValidateSeverity(tt.input)
			if tt.expected == nil {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tt.expected.Error())
			}
		})
	}
}

func TestValidateRuleAction(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected error
	}{
		{"Valid log", "log", nil},
		{"Valid detect", "detect", nil},
		{"Valid block", "block", nil},
		{"Valid challenge", "challenge", nil},
		{"Valid drop", "drop", nil},
		{"Valid redirect", "redirect", nil},
		{"Case insensitive", "BLOCK", nil},
		{"Invalid", "unknown", fmt.Errorf("invalid action. Must be: log, detect, block, challenge, drop, or redirect")},
		{"Empty", "", fmt.Errorf("invalid action. Must be: log, detect, block, challenge, drop, or redirect")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := helpers.ValidateRuleAction(tt.input)
			if tt.expected == nil {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tt.expected.Error())
			}
		})
	}
}

func TestValidateFalsePositiveStatus(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected error
	}{
		{"Valid pending", "pending", nil},
		{"Valid reviewed", "reviewed", nil},
		{"Valid whitelisted", "whitelisted", nil},
		{"Case insensitive", "PENDING", nil},
		{"Invalid", "unknown", fmt.Errorf("invalid status. Must be: pending, reviewed, or whitelisted")},
		{"Empty", "", fmt.Errorf("invalid status. Must be: pending, reviewed, or whitelisted")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := helpers.ValidateFalsePositiveStatus(tt.input)
			if tt.expected == nil {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tt.expected.Error())
			}
		})
	}
}

func TestValidateURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected error
	}{
		{"Valid full URL", "https://example.com/path?query=value", nil},
		{"Valid HTTP URL", "http://example.com", nil},
		{"Valid relative path", "/path/to/resource", nil},
		{"Valid relative path without slash", "path/to/resource", nil},
		{"Valid with query params", "/path?name=value&id=123", nil},
		{"Valid with special chars", "https://example.com/path@!$&'()*+,;=:", nil},
		{"Empty (allowed)", "", nil},
		{"Too long", "http://" + strings.Repeat("a", 1994), fmt.Errorf("URL cannot exceed 2000 characters")},
		{"Invalid protocol", "ftp://example.com", fmt.Errorf("invalid URL format")},
		{"Invalid characters", "https://example.com/<script>", fmt.Errorf("invalid URL format")},
		{"Invalid format", "://example.com", fmt.Errorf("invalid URL format")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := helpers.ValidateURL(tt.input)
			if tt.expected == nil {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tt.expected.Error())
			}
		})
	}
}

func TestValidateURL_MaxLength(t *testing.T) {
	// Test per il limite massimo di caratteri
	// Creiamo un path relativo valido di esattamente 2000 caratteri
	// Il pattern per path relativo è: ^/?[a-zA-Z0-9\-._~/?#@!$&'()*+,;=]+$
	validPath := "/" + strings.Repeat("a", 1999) // 2000 caratteri totali
	
	err := helpers.ValidateURL(validPath)
	assert.NoError(t, err, "URL di 2000 caratteri dovrebbe essere valido")
	
	// Test per URL che supera il limite
	tooLongPath := "/" + strings.Repeat("a", 2000) // 2001 caratteri
	err = helpers.ValidateURL(tooLongPath)
	assert.EqualError(t, err, "URL cannot exceed 2000 characters")
}


func TestValidateUserAgent(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected error
	}{
		{"Valid UA", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", nil},
		{"Empty (allowed)", "", nil},
		{"Too long", string(make([]byte, 501)), fmt.Errorf("user agent cannot exceed 500 characters")},
		{"Exactly 500", string(make([]byte, 500)), nil},
		{"Normal length", "Test Agent", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := helpers.ValidateUserAgent(tt.input)
			if tt.expected == nil {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tt.expected.Error())
			}
		})
	}
}

func TestValidateDescription(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected error
	}{
		{"Valid description", "This is a test description", nil},
		{"Empty (allowed)", "", nil},
		{"Too long", string(make([]byte, 501)), fmt.Errorf("description cannot exceed 500 characters")},
		{"Exactly 500", string(make([]byte, 500)), nil},
		{"With special chars", "Description with !@#$%^&*()", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := helpers.ValidateDescription(tt.input)
			if tt.expected == nil {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tt.expected.Error())
			}
		})
	}
}

func TestValidatePayload(t *testing.T) {
	// Creiamo un payload valido di esattamente 10000 caratteri
	exactPayload := string(make([]byte, 10000))
	// Creiamo un JSON valido sotto il limite (9990 caratteri interni + wrapper)
	validJSON := `{"data": "` + string(make([]byte, 9985)) + `"}` // Totale: 9995 caratteri
	
	tests := []struct {
		name     string
		input    string
		expected error
	}{
		{"Valid payload", `{"key": "value"}`, nil},
		{"Empty (allowed)", "", nil},
		{"Too long", string(make([]byte, 10001)), fmt.Errorf("payload cannot exceed 10000 characters")},
		{"Exactly 10000", exactPayload, nil},
		{"Binary data", "\x00\x01\x02\x03\x04", nil},
		{"Large JSON", validJSON, nil}, // JSON valido sotto il limite
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := helpers.ValidatePayload(tt.input)
			if tt.expected == nil {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tt.expected.Error())
			}
		})
	}
}

func TestValidateNonEmpty(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		fieldName string
		expected  error
	}{
		{"Valid non-empty", "test", "Field", nil},
		{"Empty string", "", "Field", fmt.Errorf("Field cannot be empty")},
		{"Only spaces", "   ", "Field", fmt.Errorf("Field cannot be empty")},
		{"With newlines", "\n\n", "Test Field", fmt.Errorf("Test Field cannot be empty")},
		{"With tabs", "\t\t", "Field", fmt.Errorf("Field cannot be empty")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := helpers.ValidateNonEmpty(tt.value, tt.fieldName)
			if tt.expected == nil {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tt.expected.Error())
			}
		})
	}
}

func TestValidateStringLength(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		fieldName string
		minLen    int
		maxLen    int
		expected  error
	}{
		{"Valid length", "test", "Field", 1, 10, nil},
		{"Too short", "t", "Field", 2, 10, fmt.Errorf("Field must be at least 2 characters")},
		{"Too long", "toolongtext", "Field", 1, 5, fmt.Errorf("Field cannot exceed 5 characters")},
		{"Exactly min", "ab", "Field", 2, 10, nil},
		{"Exactly max", "abcde", "Field", 1, 5, nil},
		{"With spaces", "  test  ", "Field", 1, 10, nil}, // TrimSpace is applied
		{"Empty with min 0", "", "Field", 0, 10, nil},
		{"Only spaces with min 1", "   ", "Field", 1, 10, fmt.Errorf("Field must be at least 1 characters")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := helpers.ValidateStringLength(tt.value, tt.fieldName, tt.minLen, tt.maxLen)
			if tt.expected == nil {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tt.expected.Error())
			}
		})
	}
}

func TestValidateHTTPMethod(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected error
	}{
		{"Valid GET", "GET", nil},
		{"Valid POST", "POST", nil},
		{"Valid PUT", "PUT", nil},
		{"Valid DELETE", "DELETE", nil},
		{"Valid PATCH", "PATCH", nil},
		{"Valid HEAD", "HEAD", nil},
		{"Valid OPTIONS", "OPTIONS", nil},
		{"Valid TRACE", "TRACE", nil},
		{"Valid CONNECT", "CONNECT", nil},
		{"Lowercase", "get", nil}, // CORRETTO: la funzione usa strings.ToUpper() quindi accetta anche lowercase
		{"Mixed case", "GeT", nil}, // CORRETTO: anche mixed case funziona
		{"Invalid", "INVALID", fmt.Errorf("invalid HTTP method: INVALID")},
		{"Empty (allowed)", "", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := helpers.ValidateHTTPMethod(tt.input)
			if tt.expected == nil {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tt.expected.Error())
			}
		})
	}
}

func TestValidateReviewNotes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected error
	}{
		{"Valid notes", "These are review notes", nil},
		{"Empty (allowed)", "", nil},
		{"Too long", string(make([]byte, 1001)), fmt.Errorf("review notes cannot exceed 1000 characters")},
		{"Exactly 1000", string(make([]byte, 1000)), nil},
		{"Multiline notes", "Line 1\nLine 2\nLine 3", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := helpers.ValidateReviewNotes(tt.input)
			if tt.expected == nil {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tt.expected.Error())
			}
		})
	}
}

func TestValidateIPAddress(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected error
	}{
		{"Valid IPv4", "192.168.1.1", nil},
		{"Valid IPv4 localhost", "127.0.0.1", nil},
		{"Valid IPv6", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", nil},
		{"Valid IPv6 shortened", "::1", nil},
		{"Empty", "", fmt.Errorf("IP address cannot be empty")},
		{"Invalid format", "256.256.256.256", fmt.Errorf("invalid IP address format")},
		{"Invalid characters", "192.168.1.abc", fmt.Errorf("invalid IP address format")},
		{"Missing octets", "192.168.1", fmt.Errorf("invalid IP address format")},
		{"Extra octets", "192.168.1.1.1", fmt.Errorf("invalid IP address format")},
		{"Invalid IPv6", "gggg:gggg:gggg", fmt.Errorf("invalid IP address format")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := helpers.ValidateIPAddress(tt.input)
			if tt.expected == nil {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tt.expected.Error())
			}
		})
	}
}