// tests/errors/errors_test.go
package errors_test  // Questo è corretto!

import (
	"errors"  // Importa il pacchetto standard errors
	"testing"
	
	customerrors "github.com/PiCas19/waf-siem-advanced-detection/api/internal/errors"
)

func TestRuleErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{"ErrRuleNotFound", customerrors.ErrRuleNotFound, "rule not found"},
		{"ErrRuleAlreadyExists", customerrors.ErrRuleAlreadyExists, "rule already exists"},
		{"ErrInvalidRuleData", customerrors.ErrInvalidRuleData, "invalid rule data"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.expected {
				t.Errorf("%s: expected %q, got %q", tt.name, tt.expected, tt.err.Error())
			}
		})
	}
}

func TestUserErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{"ErrUserNotFound", customerrors.ErrUserNotFound, "user not found"},
		{"ErrUserAlreadyExists", customerrors.ErrUserAlreadyExists, "user already exists"},
		{"ErrInvalidCredentials", customerrors.ErrInvalidCredentials, "invalid credentials"},
		{"ErrUnauthorized", customerrors.ErrUnauthorized, "unauthorized"},
		{"ErrForbidden", customerrors.ErrForbidden, "forbidden"},
		{"ErrInvalidUserData", customerrors.ErrInvalidUserData, "invalid user data"},
		{"ErrCannotEditOwnAccount", customerrors.ErrCannotEditOwnAccount, "cannot edit your own account"},
		{"ErrCannotDeleteOwnAccount", customerrors.ErrCannotDeleteOwnAccount, "cannot delete your own account"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.expected {
				t.Errorf("%s: expected %q, got %q", tt.name, tt.expected, tt.err.Error())
			}
		})
	}
}

func TestIPErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{"ErrInvalidIPAddress", customerrors.ErrInvalidIPAddress, "invalid IP address"},
		{"ErrIPAlreadyBlocked", customerrors.ErrIPAlreadyBlocked, "IP already blocked"},
		{"ErrIPAlreadyListed", customerrors.ErrIPAlreadyListed, "IP already in whitelist"},
		{"ErrIPNotFound", customerrors.ErrIPNotFound, "IP not found"},
		{"ErrInvalidThreatType", customerrors.ErrInvalidThreatType, "invalid threat type"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.expected {
				t.Errorf("%s: expected %q, got %q", tt.name, tt.expected, tt.err.Error())
			}
		})
	}
}

func TestAuditLogErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{"ErrLogNotFound", customerrors.ErrLogNotFound, "log not found"},
		{"ErrAuditLogNotFound", customerrors.ErrAuditLogNotFound, "audit log not found"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.expected {
				t.Errorf("%s: expected %q, got %q", tt.name, tt.expected, tt.err.Error())
			}
		})
	}
}

func TestFalsePositiveErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{"ErrFalsePositiveNotFound", customerrors.ErrFalsePositiveNotFound, "false positive not found"},
		{"ErrInvalidStatus", customerrors.ErrInvalidStatus, "invalid status"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.expected {
				t.Errorf("%s: expected %q, got %q", tt.name, tt.expected, tt.err.Error())
			}
		})
	}
}

func TestRequestValidationErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{"ErrInvalidRequest", customerrors.ErrInvalidRequest, "invalid request"},
		{"ErrMissingParameter", customerrors.ErrMissingParameter, "missing required parameter"},
		{"ErrInvalidPageSize", customerrors.ErrInvalidPageSize, "invalid page size"},
		{"ErrInvalidPageNumber", customerrors.ErrInvalidPageNumber, "invalid page number"},
		{"ErrInvalidReason", customerrors.ErrInvalidReason, "invalid reason"},
		{"ErrInvalidDuration", customerrors.ErrInvalidDuration, "invalid duration"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.expected {
				t.Errorf("%s: expected %q, got %q", tt.name, tt.expected, tt.err.Error())
			}
		})
	}
}

func TestThreatIntelligenceErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{"ErrEnrichmentFailed", customerrors.ErrEnrichmentFailed, "enrichment failed"},
		{"ErrExternalAPIError", customerrors.ErrExternalAPIError, "external API error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.expected {
				t.Errorf("%s: expected %q, got %q", tt.name, tt.expected, tt.err.Error())
			}
		})
	}
}

func TestDatabaseErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{"ErrDatabaseError", customerrors.ErrDatabaseError, "database error"},
		{"ErrOperationFailed", customerrors.ErrOperationFailed, "operation failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.expected {
				t.Errorf("%s: expected %q, got %q", tt.name, tt.expected, tt.err.Error())
			}
		})
	}
}

func TestWrapError(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		message     string
		expected    string
		shouldWrap  bool
	}{
		{
			name:       "Wrap existing error",
			err:        customerrors.ErrUserNotFound,
			message:    "Failed to fetch user",
			expected:   "Failed to fetch user: user not found",
			shouldWrap: true,
		},
		{
			name:       "Wrap nil error creates new error",
			err:        nil,
			message:    "Operation failed",
			expected:   "Operation failed",
			shouldWrap: false,
		},
		{
			name:       "Wrap standard error",
			err:        errors.New("original error"),  // Qui usa il pacchetto standard errors
			message:    "Context",
			expected:   "Context: original error",
			shouldWrap: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := customerrors.WrapError(tt.err, tt.message)
			
			if result.Error() != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result.Error())
			}

			if tt.shouldWrap && tt.err != nil {
				if result.Error() != tt.expected {
					t.Errorf("wrapped error doesn't contain original error message")
				}
			}
		})
	}
}

func TestIsError(t *testing.T) {
	// Test con errori custom
	if !customerrors.IsError(customerrors.ErrUserNotFound, customerrors.ErrUserNotFound) {
		t.Errorf("IsError should return true for same error instance")
	}

	// Test con errori diversi
	if customerrors.IsError(customerrors.ErrUserNotFound, customerrors.ErrRuleNotFound) {
		t.Errorf("IsError should return false for different error instances")
	}

	// Test con errore nil
	if customerrors.IsError(nil, customerrors.ErrUserNotFound) {
		t.Errorf("IsError should return false when err is nil")
	}

	if customerrors.IsError(customerrors.ErrUserNotFound, nil) {
		t.Errorf("IsError should return false when target is nil")
	}

	// Test con wrapped errors usando il package standard errors
	wrappedErr := errors.New("wrapped: " + customerrors.ErrUserNotFound.Error())
	if !customerrors.IsError(wrappedErr, wrappedErr) {
		t.Errorf("IsError should return true for same wrapped error instance")
	}
}

func TestAs(t *testing.T) {
	// Test per verificare che la funzione As sia disponibile
	err := customerrors.ErrUserNotFound
	var target error
	
	result := customerrors.As(err, &target)
	if !result {
		t.Log("As returned false as expected for simple errors")
	}
	
	if target != nil && target != err {
		t.Errorf("target should be nil or the original error")
	}
}

func TestErrorUniqueness(t *testing.T) {
	// Verifica che tutti gli errori abbiano messaggi unici
	allErrors := []error{
		customerrors.ErrRuleNotFound,
		customerrors.ErrRuleAlreadyExists,
		customerrors.ErrInvalidRuleData,
		customerrors.ErrUserNotFound,
		customerrors.ErrUserAlreadyExists,
		customerrors.ErrInvalidCredentials,
		customerrors.ErrUnauthorized,
		customerrors.ErrForbidden,
		customerrors.ErrInvalidUserData,
		customerrors.ErrCannotEditOwnAccount,
		customerrors.ErrCannotDeleteOwnAccount,
		customerrors.ErrInvalidIPAddress,
		customerrors.ErrIPAlreadyBlocked,
		customerrors.ErrIPAlreadyListed,
		customerrors.ErrIPNotFound,
		customerrors.ErrInvalidThreatType,
		customerrors.ErrLogNotFound,
		customerrors.ErrAuditLogNotFound,
		customerrors.ErrFalsePositiveNotFound,
		customerrors.ErrInvalidStatus,
		customerrors.ErrInvalidRequest,
		customerrors.ErrMissingParameter,
		customerrors.ErrInvalidPageSize,
		customerrors.ErrInvalidPageNumber,
		customerrors.ErrInvalidReason,
		customerrors.ErrInvalidDuration,
		customerrors.ErrEnrichmentFailed,
		customerrors.ErrExternalAPIError,
		customerrors.ErrDatabaseError,
		customerrors.ErrOperationFailed,
	}

	// Controlla duplicati
	errorMap := make(map[string]int)
	for i, err := range allErrors {
		msg := err.Error()
		if count, exists := errorMap[msg]; exists {
			t.Errorf("duplicate error message %q found at indices %d and %d", msg, count, i)
		} else {
			errorMap[msg] = i
		}
	}
}

func TestErrorMessagesAreMeaningful(t *testing.T) {
	// Verifica che i messaggi di errore siano significativi e leggibili
	tests := []struct {
		err      error
		contains []string
	}{
		{customerrors.ErrRuleNotFound, []string{"rule", "not", "found"}},
		{customerrors.ErrInvalidCredentials, []string{"invalid", "credentials"}},
		{customerrors.ErrIPAlreadyBlocked, []string{"IP", "already", "blocked"}},
		{customerrors.ErrCannotEditOwnAccount, []string{"cannot", "edit", "own", "account"}},
		{customerrors.ErrMissingParameter, []string{"missing", "required", "parameter"}},
	}

	for _, tt := range tests {
		t.Run(tt.err.Error(), func(t *testing.T) {
			msg := tt.err.Error()
			for _, word := range tt.contains {
				// Verifica che ogni parola chiave sia presente nel messaggio
				found := false
				for i := 0; i <= len(msg)-len(word); i++ {
					if msg[i:i+len(word)] == word {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("error message %q should contain word %q", msg, word)
				}
			}
		})
	}
}

func TestWrapErrorPreservesOriginalError(t *testing.T) {
	original := customerrors.ErrUserNotFound
	wrapped := customerrors.WrapError(original, "Context")
	
	// Verifica che l'errore wrapped contenga sia il contesto che l'errore originale
	wrappedStr := wrapped.Error()
	if wrappedStr != "Context: user not found" {
		t.Errorf("wrapped error should be 'Context: user not found', got %q", wrappedStr)
	}
}

func TestErrorFunctionality(t *testing.T) {
	// Verifica che gli errori implementino l'interfaccia error
	var _ error = customerrors.ErrUserNotFound
	var _ error = customerrors.ErrRuleNotFound
	var _ error = customerrors.ErrInvalidIPAddress
	
	// Tutti dovrebbero implementare l'interfaccia error
	// Se il codice compila, questo test passa
}