package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	internalapi "github.com/PiCas19/waf-siem-advanced-detection/api/internal/api"
)

// TestErrorCodeConstants tests all ErrorCode constants are properly defined
func TestErrorCodeConstants(t *testing.T) {
	// Test validation error constants
	assert.Equal(t, internalapi.ErrorCode("INVALID_JSON"), internalapi.ErrInvalidJSON)
	assert.Equal(t, internalapi.ErrorCode("INVALID_IP"), internalapi.ErrInvalidIP)
	assert.Equal(t, internalapi.ErrorCode("INVALID_EMAIL"), internalapi.ErrInvalidEmail)
	assert.Equal(t, internalapi.ErrorCode("INVALID_REQUEST"), internalapi.ErrInvalidRequest)
	assert.Equal(t, internalapi.ErrorCode("MISSING_FIELD"), internalapi.ErrMissingField)
	assert.Equal(t, internalapi.ErrorCode("INVALID_DURATION"), internalapi.ErrInvalidDuration)
	assert.Equal(t, internalapi.ErrorCode("INVALID_THREAT_TYPE"), internalapi.ErrInvalidThreatType)

	// Test resource error constants
	assert.Equal(t, internalapi.ErrorCode("NOT_FOUND"), internalapi.ErrNotFound)
	assert.Equal(t, internalapi.ErrorCode("USER_NOT_FOUND"), internalapi.ErrUserNotFound)
	assert.Equal(t, internalapi.ErrorCode("RULE_NOT_FOUND"), internalapi.ErrRuleNotFound)
	assert.Equal(t, internalapi.ErrorCode("IP_NOT_FOUND"), internalapi.ErrIPNotFound)
	assert.Equal(t, internalapi.ErrorCode("LOG_NOT_FOUND"), internalapi.ErrLogNotFound)
	assert.Equal(t, internalapi.ErrorCode("CONFLICT"), internalapi.ErrConflict)
	assert.Equal(t, internalapi.ErrorCode("DUPLICATE_ENTRY"), internalapi.ErrDuplicateEntry)

	// Test authorization error constants
	assert.Equal(t, internalapi.ErrorCode("UNAUTHORIZED"), internalapi.ErrUnauthorized)
	assert.Equal(t, internalapi.ErrorCode("FORBIDDEN"), internalapi.ErrForbidden)

	// Test business logic error constants
	assert.Equal(t, internalapi.ErrorCode("CANNOT_EDIT_MANUAL_BLOCK"), internalapi.ErrCannotEditManualBlock)
	assert.Equal(t, internalapi.ErrorCode("CANNOT_DELETE_OWN_ACCOUNT"), internalapi.ErrCannotDeleteOwnAccount)
	assert.Equal(t, internalapi.ErrorCode("CANNOT_EDIT_OWN_ACCOUNT"), internalapi.ErrCannotEditOwnAccount)
	assert.Equal(t, internalapi.ErrorCode("CANNOT_BLOCK_LOOPBACK"), internalapi.ErrCannotBlockLoopback)
	assert.Equal(t, internalapi.ErrorCode("IP_ALREADY_BLOCKED"), internalapi.ErrIPAlreadyBlocked)
	assert.Equal(t, internalapi.ErrorCode("IP_ALREADY_WHITELISTED"), internalapi.ErrIPAlreadyWhitelisted)
	assert.Equal(t, internalapi.ErrorCode("INVALID_RULE_ACTION"), internalapi.ErrInvalidRuleAction)
	assert.Equal(t, internalapi.ErrorCode("MANUAL_BLOCK_NO_REVERT"), internalapi.ErrManualBlockNoRevert)

	// Test server error constants
	assert.Equal(t, internalapi.ErrorCode("INTERNAL_SERVER_ERROR"), internalapi.ErrInternalServer)
	assert.Equal(t, internalapi.ErrorCode("DATABASE_ERROR"), internalapi.ErrDatabaseError)
	assert.Equal(t, internalapi.ErrorCode("SERVICE_ERROR"), internalapi.ErrServiceError)
}

// TestErrorDetailStruct tests the ErrorDetail struct
func TestErrorDetailStruct(t *testing.T) {
	// Test struct creation with details
	detail := internalapi.ErrorDetail{
		Code:    internalapi.ErrInvalidJSON,
		Message: "Invalid JSON format",
		Details: "Check your request body",
	}

	assert.Equal(t, internalapi.ErrInvalidJSON, detail.Code)
	assert.Equal(t, "Invalid JSON format", detail.Message)
	assert.Equal(t, "Check your request body", detail.Details)

	// Test struct without details
	detailWithoutDetails := internalapi.ErrorDetail{
		Code:    internalapi.ErrNotFound,
		Message: "Resource not found",
	}

	assert.Equal(t, internalapi.ErrNotFound, detailWithoutDetails.Code)
	assert.Equal(t, "Resource not found", detailWithoutDetails.Message)
	assert.Empty(t, detailWithoutDetails.Details)

	// Test JSON marshaling with details
	jsonData, err := json.Marshal(detail)
	assert.NoError(t, err)

	expectedJSON := `{"code":"INVALID_JSON","message":"Invalid JSON format","details":"Check your request body"}`
	assert.JSONEq(t, expectedJSON, string(jsonData))

	// Test JSON marshaling without details (should omit empty field)
	jsonDataWithoutDetails, err := json.Marshal(detailWithoutDetails)
	assert.NoError(t, err)

	expectedJSONWithoutDetails := `{"code":"NOT_FOUND","message":"Resource not found"}`
	assert.JSONEq(t, expectedJSONWithoutDetails, string(jsonDataWithoutDetails))
}


// TestErrorResponseWithCode tests basic error response
func TestErrorResponseWithCode(t *testing.T) {
	// Set Gin to test mode
	gin.SetMode(gin.TestMode)

	// Create test router
	router := gin.New()
	router.GET("/test-error", func(c *gin.Context) {
		internalapi.ErrorResponseWithCode(c, http.StatusBadRequest, internalapi.ErrInvalidJSON, "Invalid JSON format")
	})

	// Create test request
	req, err := http.NewRequest("GET", "/test-error", nil)
	assert.NoError(t, err)

	// Record response
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Verify response
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response internalapi.ErrorDetail
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)

	assert.Equal(t, internalapi.ErrInvalidJSON, response.Code)
	assert.Equal(t, "Invalid JSON format", response.Message)
	assert.Empty(t, response.Details)
}

// TestErrorResponseWithDetails tests error response with additional details
func TestErrorResponseWithDetails(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/test-error-details", func(c *gin.Context) {
		internalapi.ErrorResponseWithDetails(c, http.StatusBadRequest, internalapi.ErrInvalidRequest, 
			"Invalid request parameters", "The 'limit' parameter must be positive")
	})

	req, err := http.NewRequest("GET", "/test-error-details", nil)
	assert.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response internalapi.ErrorDetail
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)

	assert.Equal(t, internalapi.ErrInvalidRequest, response.Code)
	assert.Equal(t, "Invalid request parameters", response.Message)
	assert.Equal(t, "The 'limit' parameter must be positive", response.Details)
}

// TestErrorResponseWithDetails_EmptyDetails tests with empty details
func TestErrorResponseWithDetails_EmptyDetails(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/test-empty-details", func(c *gin.Context) {
		internalapi.ErrorResponseWithDetails(c, http.StatusBadRequest, internalapi.ErrMissingField, 
			"Required field is missing", "")
	})

	req, err := http.NewRequest("GET", "/test-empty-details", nil)
	assert.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	// The details field may be omitted since it's empty
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)

	assert.Equal(t, "MISSING_FIELD", response["code"])
	assert.Equal(t, "Required field is missing", response["message"])
	// Details may or may not be present, but if present should be empty string
	if details, exists := response["details"]; exists {
		assert.Equal(t, "", details)
	}
}

// TestBadRequestWithCode tests 400 Bad Request helper
func TestBadRequestWithCode(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/test-bad-request", func(c *gin.Context) {
		internalapi.BadRequestWithCode(c, internalapi.ErrInvalidIP, "Invalid IP address format")
	})

	req, err := http.NewRequest("GET", "/test-bad-request", nil)
	assert.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response internalapi.ErrorDetail
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)

	assert.Equal(t, internalapi.ErrInvalidIP, response.Code)
	assert.Equal(t, "Invalid IP address format", response.Message)
	assert.Empty(t, response.Details)
}

// TestBadRequestWithDetails tests 400 Bad Request with details
func TestBadRequestWithDetails(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/test-bad-request-details", func(c *gin.Context) {
		internalapi.BadRequestWithDetails(c, internalapi.ErrInvalidDuration, "Invalid duration format", 
			"Duration must be in format '1h', '2d', '3w'")
	})

	req, err := http.NewRequest("GET", "/test-bad-request-details", nil)
	assert.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response internalapi.ErrorDetail
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)

	assert.Equal(t, internalapi.ErrInvalidDuration, response.Code)
	assert.Equal(t, "Invalid duration format", response.Message)
	assert.Equal(t, "Duration must be in format '1h', '2d', '3w'", response.Details)
}

// TestUnauthorizedWithCode tests 401 Unauthorized helper
func TestUnauthorizedWithCode(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/test-unauthorized", func(c *gin.Context) {
		internalapi.UnauthorizedWithCode(c, internalapi.ErrUnauthorized, "Authentication required")
	})

	req, err := http.NewRequest("GET", "/test-unauthorized", nil)
	assert.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response internalapi.ErrorDetail
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)

	assert.Equal(t, internalapi.ErrUnauthorized, response.Code)
	assert.Equal(t, "Authentication required", response.Message)
	assert.Empty(t, response.Details)
}

// TestForbiddenWithCode tests 403 Forbidden helper
func TestForbiddenWithCode(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/test-forbidden", func(c *gin.Context) {
		internalapi.ForbiddenWithCode(c, internalapi.ErrForbidden, "Insufficient permissions")
	})

	req, err := http.NewRequest("GET", "/test-forbidden", nil)
	assert.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)

	var response internalapi.ErrorDetail
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)

	assert.Equal(t, internalapi.ErrForbidden, response.Code)
	assert.Equal(t, "Insufficient permissions", response.Message)
	assert.Empty(t, response.Details)
}

// TestNotFoundWithCode tests 404 Not Found helper
func TestNotFoundWithCode(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/test-not-found", func(c *gin.Context) {
		internalapi.NotFoundWithCode(c, internalapi.ErrUserNotFound, "User not found")
	})

	req, err := http.NewRequest("GET", "/test-not-found", nil)
	assert.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var response internalapi.ErrorDetail
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)

	assert.Equal(t, internalapi.ErrUserNotFound, response.Code)
	assert.Equal(t, "User not found", response.Message)
	assert.Empty(t, response.Details)
}

// TestConflictWithCode tests 409 Conflict helper
func TestConflictWithCode(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/test-conflict", func(c *gin.Context) {
		internalapi.ConflictWithCode(c, internalapi.ErrDuplicateEntry, "Resource already exists")
	})

	req, err := http.NewRequest("GET", "/test-conflict", nil)
	assert.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)

	var response internalapi.ErrorDetail
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)

	assert.Equal(t, internalapi.ErrDuplicateEntry, response.Code)
	assert.Equal(t, "Resource already exists", response.Message)
	assert.Empty(t, response.Details)
}

// TestInternalServerErrorWithCode tests 500 Internal Server Error helper
func TestInternalServerErrorWithCode(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/test-internal-error", func(c *gin.Context) {
		internalapi.InternalServerErrorWithCode(c, internalapi.ErrDatabaseError, "Database connection failed")
	})

	req, err := http.NewRequest("GET", "/test-internal-error", nil)
	assert.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var response internalapi.ErrorDetail
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)

	assert.Equal(t, internalapi.ErrDatabaseError, response.Code)
	assert.Equal(t, "Database connection failed", response.Message)
	assert.Empty(t, response.Details)
}

// TestAllErrorHelpersTogether tests multiple error helpers in sequence
func TestAllErrorHelpersTogether(t *testing.T) {
	gin.SetMode(gin.TestMode)

	testCases := []struct {
		name       string
		handler    func(*gin.Context)
		statusCode int
		errorCode  internalapi.ErrorCode
		message    string
	}{
		{
			name: "BadRequestWithCode",
			handler: func(c *gin.Context) {
				internalapi.BadRequestWithCode(c, internalapi.ErrInvalidEmail, "Invalid email format")
			},
			statusCode: http.StatusBadRequest,
			errorCode:  internalapi.ErrInvalidEmail,
			message:    "Invalid email format",
		},
		{
			name: "UnauthorizedWithCode",
			handler: func(c *gin.Context) {
				internalapi.UnauthorizedWithCode(c, internalapi.ErrUnauthorized, "Token expired")
			},
			statusCode: http.StatusUnauthorized,
			errorCode:  internalapi.ErrUnauthorized,
			message:    "Token expired",
		},
		{
			name: "ForbiddenWithCode",
			handler: func(c *gin.Context) {
				internalapi.ForbiddenWithCode(c, internalapi.ErrForbidden, "Admin access required")
			},
			statusCode: http.StatusForbidden,
			errorCode:  internalapi.ErrForbidden,
			message:    "Admin access required",
		},
		{
			name: "NotFoundWithCode",
			handler: func(c *gin.Context) {
				internalapi.NotFoundWithCode(c, internalapi.ErrRuleNotFound, "Security rule not found")
			},
			statusCode: http.StatusNotFound,
			errorCode:  internalapi.ErrRuleNotFound,
			message:    "Security rule not found",
		},
		{
			name: "ConflictWithCode",
			handler: func(c *gin.Context) {
				internalapi.ConflictWithCode(c, internalapi.ErrIPAlreadyBlocked, "IP is already blocked")
			},
			statusCode: http.StatusConflict,
			errorCode:  internalapi.ErrIPAlreadyBlocked,
			message:    "IP is already blocked",
		},
		{
			name: "InternalServerErrorWithCode",
			handler: func(c *gin.Context) {
				internalapi.InternalServerErrorWithCode(c, internalapi.ErrServiceError, "External service unavailable")
			},
			statusCode: http.StatusInternalServerError,
			errorCode:  internalapi.ErrServiceError,
			message:    "External service unavailable",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			router := gin.New()
			router.GET("/test", tc.handler)

			req, err := http.NewRequest("GET", "/test", nil)
			assert.NoError(t, err)

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tc.statusCode, w.Code)

			var response internalapi.ErrorDetail
			err = json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)

			assert.Equal(t, tc.errorCode, response.Code)
			assert.Equal(t, tc.message, response.Message)
		})
	}
}

// TestErrorResponseJSONStructure tests complete JSON structure of error responses
func TestErrorResponseJSONStructure(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/test-json", func(c *gin.Context) {
		internalapi.BadRequestWithDetails(c, internalapi.ErrInvalidThreatType, 
			"Invalid threat type specified", 
			"Valid types: xss, sqli, rfi, lfi, command_injection")
	})

	req, err := http.NewRequest("GET", "/test-json", nil)
	assert.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Parse JSON to check structure
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)

	// Check all fields exist
	assert.Contains(t, response, "code")
	assert.Contains(t, response, "message")
	assert.Contains(t, response, "details")

	// Check field types
	assert.IsType(t, "", response["code"])
	assert.IsType(t, "", response["message"])
	assert.IsType(t, "", response["details"])

	// Check values
	assert.Equal(t, "INVALID_THREAT_TYPE", response["code"])
	assert.Equal(t, "Invalid threat type specified", response["message"])
	assert.Equal(t, "Valid types: xss, sqli, rfi, lfi, command_injection", response["details"])
}

// TestErrorDetailJSONMarshalUnmarshal tests full JSON marshaling/unmarshaling cycle
func TestErrorDetailJSONMarshalUnmarshal(t *testing.T) {
	// Test marshaling
	original := internalapi.ErrorDetail{
		Code:    internalapi.ErrCannotEditManualBlock,
		Message: "Manual blocks cannot be edited",
		Details: "Only automatic blocks can be modified",
	}

	jsonData, err := json.Marshal(original)
	assert.NoError(t, err)

	// Test unmarshaling
	var unmarshaled internalapi.ErrorDetail
	err = json.Unmarshal(jsonData, &unmarshaled)
	assert.NoError(t, err)

	// Compare
	assert.Equal(t, original.Code, unmarshaled.Code)
	assert.Equal(t, original.Message, unmarshaled.Message)
	assert.Equal(t, original.Details, unmarshaled.Details)
}

// TestErrorDetailEmptyDetailsJSON tests JSON with empty details field
func TestErrorDetailEmptyDetailsJSON(t *testing.T) {
	detail := internalapi.ErrorDetail{
		Code:    internalapi.ErrCannotBlockLoopback,
		Message: "Loopback addresses cannot be blocked",
		// Details intentionally omitted
	}

	jsonData, err := json.Marshal(detail)
	assert.NoError(t, err)

	// Parse back
	var parsed map[string]interface{}
	err = json.Unmarshal(jsonData, &parsed)
	assert.NoError(t, err)

	// Should NOT have details field since it's empty and has omitempty tag
	assert.Equal(t, "CANNOT_BLOCK_LOOPBACK", parsed["code"])
	assert.Equal(t, "Loopback addresses cannot be blocked", parsed["message"])
	assert.NotContains(t, parsed, "details") // Should not contain details field
}

// TestErrorDetailOmitEmpty tests that empty details field is included in JSON
func TestErrorDetailOmitEmpty(t *testing.T) {
	detail := internalapi.ErrorDetail{
		Code:    internalapi.ErrManualBlockNoRevert,
		Message: "Manual blocks cannot be reverted automatically",
	}

	jsonData, err := json.Marshal(detail)
	assert.NoError(t, err)

	// The details field should be OMITTED since it's empty and has omitempty tag
	var parsed map[string]interface{}
	err = json.Unmarshal(jsonData, &parsed)
	assert.NoError(t, err)

	assert.NotContains(t, parsed, "details") // Should be omitted, not present
	assert.Equal(t, "MANUAL_BLOCK_NO_REVERT", parsed["code"])
	assert.Equal(t, "Manual blocks cannot be reverted automatically", parsed["message"])
}

// TestBusinessLogicErrorCodes tests all business logic error codes
func TestBusinessLogicErrorCodes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	testCases := []struct {
		errorCode  internalapi.ErrorCode
		message    string
		statusCode int
	}{
		{
			errorCode:  internalapi.ErrCannotEditManualBlock,
			message:    "Cannot edit manual block entry",
			statusCode: http.StatusBadRequest,
		},
		{
			errorCode:  internalapi.ErrCannotDeleteOwnAccount,
			message:    "You cannot delete your own account",
			statusCode: http.StatusForbidden,
		},
		{
			errorCode:  internalapi.ErrCannotEditOwnAccount,
			message:    "You cannot edit your own account",
			statusCode: http.StatusForbidden,
		},
		{
			errorCode:  internalapi.ErrCannotBlockLoopback,
			message:    "Cannot block loopback addresses",
			statusCode: http.StatusBadRequest,
		},
		{
			errorCode:  internalapi.ErrIPAlreadyBlocked,
			message:    "IP address is already blocked",
			statusCode: http.StatusConflict,
		},
		{
			errorCode:  internalapi.ErrIPAlreadyWhitelisted,
			message:    "IP address is already whitelisted",
			statusCode: http.StatusConflict,
		},
		{
			errorCode:  internalapi.ErrInvalidRuleAction,
			message:    "Invalid rule action specified",
			statusCode: http.StatusBadRequest,
		},
		{
			errorCode:  internalapi.ErrManualBlockNoRevert,
			message:    "Manual blocks cannot be reverted",
			statusCode: http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(string(tc.errorCode), func(t *testing.T) {
			router := gin.New()
			
			// Use appropriate helper based on status code
			router.GET("/test", func(c *gin.Context) {
				switch tc.statusCode {
				case http.StatusBadRequest:
					internalapi.BadRequestWithCode(c, tc.errorCode, tc.message)
				case http.StatusForbidden:
					internalapi.ForbiddenWithCode(c, tc.errorCode, tc.message)
				case http.StatusConflict:
					internalapi.ConflictWithCode(c, tc.errorCode, tc.message)
				default:
					internalapi.ErrorResponseWithCode(c, tc.statusCode, tc.errorCode, tc.message)
				}
			})

			req, err := http.NewRequest("GET", "/test", nil)
			assert.NoError(t, err)

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tc.statusCode, w.Code)

			var response internalapi.ErrorDetail
			err = json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)

			assert.Equal(t, tc.errorCode, response.Code)
			assert.Equal(t, tc.message, response.Message)
		})
	}
}

// TestErrorResponseWithCodeDifferentStatusCodes tests ErrorResponseWithCode with various status codes
func TestErrorResponseWithCodeDifferentStatusCodes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	statusCodes := []int{
		http.StatusBadRequest,          // 400
		http.StatusUnauthorized,        // 401
		http.StatusPaymentRequired,     // 402
		http.StatusForbidden,          // 403
		http.StatusNotFound,           // 404
		http.StatusMethodNotAllowed,   // 405
		http.StatusConflict,           // 409
		http.StatusInternalServerError, // 500
		http.StatusNotImplemented,      // 501
		http.StatusBadGateway,         // 502
		http.StatusServiceUnavailable, // 503
	}

	for _, statusCode := range statusCodes {
		t.Run(http.StatusText(statusCode), func(t *testing.T) {
			router := gin.New()
			router.GET("/test", func(c *gin.Context) {
				internalapi.ErrorResponseWithCode(c, statusCode, internalapi.ErrInternalServer, "Test error")
			})

			req, err := http.NewRequest("GET", "/test", nil)
			assert.NoError(t, err)

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, statusCode, w.Code)

			var response internalapi.ErrorDetail
			err = json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)

			assert.Equal(t, internalapi.ErrInternalServer, response.Code)
			assert.Equal(t, "Test error", response.Message)
		})
	}
}

// TestErrorResponseChain tests that error response functions properly chain
func TestErrorResponseChain(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/test-chain", func(c *gin.Context) {
		// Test that BadRequestWithCode internally calls ErrorResponseWithCode
		internalapi.BadRequestWithCode(c, internalapi.ErrInvalidRequest, "Test message")
	})

	req, err := http.NewRequest("GET", "/test-chain", nil)
	assert.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response internalapi.ErrorDetail
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)

	assert.Equal(t, internalapi.ErrInvalidRequest, response.Code)
	assert.Equal(t, "Test message", response.Message)
}

// TestBadRequestWithDetailsChain tests the function chain
func TestBadRequestWithDetailsChain(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/test-details-chain", func(c *gin.Context) {
		internalapi.BadRequestWithDetails(c, internalapi.ErrMissingField, "Field is required", "The 'email' field is missing")
	})

	req, err := http.NewRequest("GET", "/test-details-chain", nil)
	assert.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response internalapi.ErrorDetail
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)

	assert.Equal(t, internalapi.ErrMissingField, response.Code)
	assert.Equal(t, "Field is required", response.Message)
	assert.Equal(t, "The 'email' field is missing", response.Details)
}

func TestErrorDetailWithDetailsJSON(t *testing.T) {
	detail := internalapi.ErrorDetail{
		Code:    internalapi.ErrCannotEditManualBlock,
		Message: "Manual blocks cannot be edited",
		Details: "Only automatic blocks can be modified",
	}

	jsonData, err := json.Marshal(detail)
	assert.NoError(t, err)

	// Parse back
	var parsed map[string]interface{}
	err = json.Unmarshal(jsonData, &parsed)
	assert.NoError(t, err)

	// Should have all three fields since details is not empty
	assert.Equal(t, "CANNOT_EDIT_MANUAL_BLOCK", parsed["code"])
	assert.Equal(t, "Manual blocks cannot be edited", parsed["message"])
	assert.Equal(t, "Only automatic blocks can be modified", parsed["details"])
	assert.Contains(t, parsed, "details") // Should contain details field
}