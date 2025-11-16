package errors

import "errors"

// Custom error types per type-safe error handling

var (
	// Rule errors
	ErrRuleNotFound      = errors.New("rule not found")
	ErrRuleAlreadyExists = errors.New("rule already exists")
	ErrInvalidRuleData   = errors.New("invalid rule data")

	// User errors
	ErrUserNotFound           = errors.New("user not found")
	ErrUserAlreadyExists      = errors.New("user already exists")
	ErrInvalidCredentials     = errors.New("invalid credentials")
	ErrUnauthorized           = errors.New("unauthorized")
	ErrForbidden              = errors.New("forbidden")
	ErrInvalidUserData        = errors.New("invalid user data")
	ErrCannotEditOwnAccount   = errors.New("cannot edit your own account")
	ErrCannotDeleteOwnAccount = errors.New("cannot delete your own account")

	// IP errors
	ErrInvalidIPAddress  = errors.New("invalid IP address")
	ErrIPAlreadyBlocked  = errors.New("IP already blocked")
	ErrIPAlreadyListed   = errors.New("IP already in whitelist")
	ErrIPNotFound        = errors.New("IP not found")
	ErrInvalidThreatType = errors.New("invalid threat type")

	// Audit/Log errors
	ErrLogNotFound      = errors.New("log not found")
	ErrAuditLogNotFound = errors.New("audit log not found")

	// False positive errors
	ErrFalsePositiveNotFound = errors.New("false positive not found")
	ErrInvalidStatus         = errors.New("invalid status")

	// Request/Validation errors
	ErrInvalidRequest      = errors.New("invalid request")
	ErrMissingParameter    = errors.New("missing required parameter")
	ErrInvalidPageSize     = errors.New("invalid page size")
	ErrInvalidPageNumber   = errors.New("invalid page number")
	ErrInvalidReason       = errors.New("invalid reason")
	ErrInvalidDuration     = errors.New("invalid duration")

	// Threat intelligence errors
	ErrEnrichmentFailed = errors.New("enrichment failed")
	ErrExternalAPIError = errors.New("external API error")

	// Database errors
	ErrDatabaseError   = errors.New("database error")
	ErrOperationFailed = errors.New("operation failed")
)

// WrapError wraps un errore con contesto
func WrapError(err error, message string) error {
	if err == nil {
		return errors.New(message)
	}
	return errors.New(message + ": " + err.Error())
}

// IsError verifica se l'errore è di un tipo specifico
func IsError(err, target error) bool {
	return errors.Is(err, target)
}

// As converte un errore a un tipo specifico
func As(err error, target interface{}) bool {
	return errors.As(err, target)
}
