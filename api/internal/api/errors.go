package api

import (
	"github.com/gin-gonic/gin"
)

// ErrorCode defines standardized error codes for API responses
type ErrorCode string

const (
	// Validation errors
	ErrInvalidJSON       ErrorCode = "INVALID_JSON"
	ErrInvalidIP         ErrorCode = "INVALID_IP"
	ErrInvalidEmail      ErrorCode = "INVALID_EMAIL"
	ErrInvalidRequest    ErrorCode = "INVALID_REQUEST"
	ErrMissingField      ErrorCode = "MISSING_FIELD"
	ErrInvalidDuration   ErrorCode = "INVALID_DURATION"
	ErrInvalidThreatType ErrorCode = "INVALID_THREAT_TYPE"

	// Resource errors
	ErrNotFound       ErrorCode = "NOT_FOUND"
	ErrUserNotFound   ErrorCode = "USER_NOT_FOUND"
	ErrRuleNotFound   ErrorCode = "RULE_NOT_FOUND"
	ErrIPNotFound     ErrorCode = "IP_NOT_FOUND"
	ErrLogNotFound    ErrorCode = "LOG_NOT_FOUND"
	ErrConflict       ErrorCode = "CONFLICT"
	ErrDuplicateEntry ErrorCode = "DUPLICATE_ENTRY"

	// Authorization errors
	ErrUnauthorized ErrorCode = "UNAUTHORIZED"
	ErrForbidden    ErrorCode = "FORBIDDEN"

	// Business logic errors
	ErrCannotEditManualBlock   ErrorCode = "CANNOT_EDIT_MANUAL_BLOCK"
	ErrCannotDeleteOwnAccount  ErrorCode = "CANNOT_DELETE_OWN_ACCOUNT"
	ErrCannotEditOwnAccount    ErrorCode = "CANNOT_EDIT_OWN_ACCOUNT"
	ErrCannotBlockLoopback     ErrorCode = "CANNOT_BLOCK_LOOPBACK"
	ErrIPAlreadyBlocked        ErrorCode = "IP_ALREADY_BLOCKED"
	ErrIPAlreadyWhitelisted    ErrorCode = "IP_ALREADY_WHITELISTED"
	ErrInvalidRuleAction       ErrorCode = "INVALID_RULE_ACTION"
	ErrManualBlockNoRevert     ErrorCode = "MANUAL_BLOCK_NO_REVERT"

	// Server errors
	ErrInternalServer ErrorCode = "INTERNAL_SERVER_ERROR"
	ErrDatabaseError  ErrorCode = "DATABASE_ERROR"
	ErrServiceError   ErrorCode = "SERVICE_ERROR"
)

// ErrorDetail contains error information with code and details
type ErrorDetail struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
	Details string    `json:"details,omitempty"` // Optional additional info
}

// ErrorResponseWithCode sends a standardized error response with error code
func ErrorResponseWithCode(c *gin.Context, statusCode int, code ErrorCode, message string) {
	c.JSON(statusCode, ErrorDetail{
		Code:    code,
		Message: message,
	})
}

// ErrorResponseWithDetails sends error response with additional details
func ErrorResponseWithDetails(c *gin.Context, statusCode int, code ErrorCode, message string, details string) {
	c.JSON(statusCode, ErrorDetail{
		Code:    code,
		Message: message,
		Details: details,
	})
}

// BadRequestWithCode sends 400 with error code
func BadRequestWithCode(c *gin.Context, code ErrorCode, message string) {
	ErrorResponseWithCode(c, 400, code, message)
}

// BadRequestWithDetails sends 400 with error code and details
func BadRequestWithDetails(c *gin.Context, code ErrorCode, message string, details string) {
	ErrorResponseWithDetails(c, 400, code, message, details)
}

// UnauthorizedWithCode sends 401 with error code
func UnauthorizedWithCode(c *gin.Context, code ErrorCode, message string) {
	ErrorResponseWithCode(c, 401, code, message)
}

// ForbiddenWithCode sends 403 with error code
func ForbiddenWithCode(c *gin.Context, code ErrorCode, message string) {
	ErrorResponseWithCode(c, 403, code, message)
}

// NotFoundWithCode sends 404 with error code
func NotFoundWithCode(c *gin.Context, code ErrorCode, message string) {
	ErrorResponseWithCode(c, 404, code, message)
}

// ConflictWithCode sends 409 with error code
func ConflictWithCode(c *gin.Context, code ErrorCode, message string) {
	ErrorResponseWithCode(c, 409, code, message)
}

// InternalServerErrorWithCode sends 500 with error code
func InternalServerErrorWithCode(c *gin.Context, code ErrorCode, message string) {
	ErrorResponseWithCode(c, 500, code, message)
}
