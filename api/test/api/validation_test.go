package api

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/api"
)

func TestValidateIP(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		expectedIP  string
	}{
		{
			name:        "valid ipv4",
			input:       "192.168.1.1",
			expectError: false,
			expectedIP:  "192.168.1.1",
		},
		{
			name:        "valid ipv4 with whitespace",
			input:       "  10.0.0.1  ",
			expectError: false,
			expectedIP:  "10.0.0.1",
		},
		{
			name:        "valid ipv6",
			input:       "2001:db8::1",
			expectError: false,
			expectedIP:  "2001:db8::1",
		},
		{
			name:        "loopback ipv4",
			input:       "127.0.0.1",
			expectError: true,
		},
		{
			name:        "loopback ipv6",
			input:       "::1",
			expectError: true,
		},
		{
			name:        "empty string",
			input:       "",
			expectError: true,
		},
		{
			name:        "invalid format",
			input:       "not.an.ip.address",
			expectError: true,
		},
		{
			name:        "partial ip",
			input:       "192.168.1",
			expectError: true,
		},
		{
			name:        "ip with invalid char",
			input:       "192.168.1.256",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := api.ValidateIP(tt.input)

			if tt.expectError {
				assert.Error(t, err, "expected error for input: %s", tt.input)
			} else {
				assert.NoError(t, err, "expected no error for input: %s", tt.input)
				assert.Equal(t, tt.expectedIP, result)
			}
		})
	}
}

func TestValidateReason(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
	}{
		{
			name:        "valid reason",
			input:       "Suspicious activity detected",
			expectError: false,
		},
		{
			name:        "valid reason with special chars",
			input:       "Attack attempt (SQLi) from 192.168.1.1",
			expectError: false,
		},
		{
			name:        "valid reason with punctuation",
			input:       "IP compromised; needs blocking.",
			expectError: false,
		},
		{
			name:        "valid reason with slashes",
			input:       "C2/botnet command & control server",
			expectError: false,
		},
		{
			name:        "empty string",
			input:       "",
			expectError: true,
		},
		{
			name:        "only whitespace",
			input:       "   ",
			expectError: true,
		},
		{
			name:        "too long reason",
			input:       "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum and more text to exceed 500 chars",
			expectError: true,
		},
		{
			name:        "reason with invalid chars",
			input:       "Attack with <script> tags",
			expectError: true,
		},
		{
			name:        "reason with quotes",
			input:       "IP blocked for 'suspicious' behavior",
			expectError: false,
		},
		{
			name:        "reason with brackets",
			input:       "[ALERT] Malicious IP detected",
			expectError: false,
		},
		{
			name:        "exactly 500 chars",
			input:       "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum text",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := api.ValidateReason(tt.input)

			if tt.expectError {
				assert.Error(t, err, "expected error for: %s", tt.input)
			} else {
				assert.NoError(t, err, "expected no error for: %s", tt.input)
			}
		})
	}
}

func TestValidateThreat(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
	}{
		{
			name:        "valid threat type XSS",
			input:       "XSS",
			expectError: false,
		},
		{
			name:        "valid threat type SQL_INJECTION",
			input:       "SQL_INJECTION",
			expectError: false,
		},
		{
			name:        "valid custom threat",
			input:       "Custom_Rule_123",
			expectError: false,
		},
		{
			name:        "valid threat with spaces",
			input:       "Custom Threat Type",
			expectError: false,
		},
		{
			name:        "empty string",
			input:       "",
			expectError: true,
		},
		{
			name:        "only whitespace",
			input:       "   ",
			expectError: true,
		},
		{
			name:        "too long threat",
			input:       "This is a very long threat type name that exceeds the 255 character limit and should fail validation because it is way too long for a threat type identifier and exceeds all reasonable limits for such a field name",
			expectError: true,
		},
		{
			name:        "threat with invalid chars",
			input:       "Custom<Script>Threat",
			expectError: true,
		},
		{
			name:        "threat with special chars",
			input:       "Threat@Type#Invalid",
			expectError: true,
		},
		{
			name:        "exactly 255 chars",
			input:       "Custom_Rule_That_Is_Exactly_Two_Hundred_And_Fifty_Five_Characters_Long_Custom_Rule_That_Is_Exactly_Two_Hundred_And_Fifty_Five_Characters_Long_Custom_Rule_That_Is_Exactly_Two_Hundred_And_Fifty_Five_Characters_Long_Custom_Rule_That_Is_Exactly_Two_Hundred_And_Fifty_F",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := api.ValidateThreat(tt.input)

			if tt.expectError {
				assert.Error(t, err, "expected error for: %s", tt.input)
			} else {
				assert.NoError(t, err, "expected no error for: %s", tt.input)
			}
		})
	}
}

func TestValidateDuration(t *testing.T) {
	tests := []struct {
		name        string
		input       int
		expectError bool
	}{
		{
			name:        "permanent duration",
			input:       -1,
			expectError: false,
		},
		{
			name:        "1 hour duration",
			input:       1,
			expectError: false,
		},
		{
			name:        "24 hours duration",
			input:       24,
			expectError: false,
		},
		{
			name:        "7 days duration",
			input:       168,
			expectError: false,
		},
		{
			name:        "1 year duration",
			input:       8760,
			expectError: false,
		},
		{
			name:        "10 years duration (max)",
			input:       87600,
			expectError: false,
		},
		{
			name:        "zero duration",
			input:       0,
			expectError: true,
		},
		{
			name:        "negative duration (except -1)",
			input:       -10,
			expectError: true,
		},
		{
			name:        "exceeds 10 years",
			input:       87601,
			expectError: true,
		},
		{
			name:        "exceeds 10 years significantly",
			input:       100000,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := api.ValidateDuration(tt.input)

			if tt.expectError {
				assert.Error(t, err, "expected error for duration: %d", tt.input)
			} else {
				assert.NoError(t, err, "expected no error for duration: %d", tt.input)
			}
		})
	}
}
