package api

import (
	"github.com/gin-gonic/gin"
)

// ErrorResponse sends a standardized error response
func ErrorResponse(c *gin.Context, statusCode int, message string) {
	c.JSON(statusCode, gin.H{"error": message})
}

// BadRequest sends a 400 Bad Request response
func BadRequest(c *gin.Context, message string) {
	ErrorResponse(c, 400, message)
}

// Unauthorized sends a 401 Unauthorized response
func Unauthorized(c *gin.Context, message string) {
	ErrorResponse(c, 401, message)
}

// Forbidden sends a 403 Forbidden response
func Forbidden(c *gin.Context, message string) {
	ErrorResponse(c, 403, message)
}

// NotFound sends a 404 Not Found response
func NotFound(c *gin.Context, message string) {
	ErrorResponse(c, 404, message)
}

// InternalServerError sends a 500 Internal Server Error response
func InternalServerError(c *gin.Context, message string) {
	ErrorResponse(c, 500, message)
}

// ConflictError sends a 409 Conflict response
func ConflictError(c *gin.Context, message string) {
	ErrorResponse(c, 409, message)
}

// SuccessResponse sends a standardized success response
func SuccessResponse(c *gin.Context, statusCode int, data interface{}) {
	c.JSON(statusCode, data)
}

// ValidateJSON validates and binds JSON request body
// Returns true if validation passes, false otherwise and sends error response
func ValidateJSON(c *gin.Context, req interface{}) bool {
	if err := c.ShouldBindJSON(req); err != nil {
		BadRequestWithCode(c, ErrInvalidJSON, "Invalid JSON format")
		return false
	}
	return true
}
