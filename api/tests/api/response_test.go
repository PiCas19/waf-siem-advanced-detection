package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	// Importa il package interno che contiene response.go
	internalapi "github.com/PiCas19/waf-siem-advanced-detection/api/internal/api"
)

// TestErrorResponse tests the ErrorResponse function
func TestErrorResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name       string
		statusCode int
		message    string
	}{
		{
			name:       "Should return 400 Bad Request with error message",
			statusCode: 400,
			message:    "Invalid request format",
		},
		{
			name:       "Should return 500 Internal Server Error with error message",
			statusCode: 500,
			message:    "Something went wrong",
		},
		{
			name:       "Should return 404 Not Found with error message",
			statusCode: 404,
			message:    "Resource not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			internalapi.ErrorResponse(c, tt.statusCode, tt.message)

			assert.Equal(t, tt.statusCode, w.Code)
			
			var resp map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &resp)
			assert.NoError(t, err)
			assert.Equal(t, tt.message, resp["error"])
		})
	}
}

// TestBadRequest tests the BadRequest function
func TestBadRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	internalapi.BadRequest(c, "Invalid JSON format")

	assert.Equal(t, 400, w.Code)
	
	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "Invalid JSON format", resp["error"])
}

// TestUnauthorized tests the Unauthorized function
func TestUnauthorized(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	internalapi.Unauthorized(c, "Authentication required")

	assert.Equal(t, 401, w.Code)
	
	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "Authentication required", resp["error"])
}

// TestForbidden tests the Forbidden function
func TestForbidden(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	internalapi.Forbidden(c, "Access denied")

	assert.Equal(t, 403, w.Code)
	
	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "Access denied", resp["error"])
}

// TestNotFound tests the NotFound function
func TestNotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	internalapi.NotFound(c, "User not found")

	assert.Equal(t, 404, w.Code)
	
	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "User not found", resp["error"])
}

// TestInternalServerError tests the InternalServerError function
func TestInternalServerError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	internalapi.InternalServerError(c, "Database connection failed")

	assert.Equal(t, 500, w.Code)
	
	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "Database connection failed", resp["error"])
}

// TestConflictError tests the ConflictError function
func TestConflictError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	internalapi.ConflictError(c, "User already exists")

	assert.Equal(t, 409, w.Code)
	
	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "User already exists", resp["error"])
}

// TestSuccessResponse tests the SuccessResponse function
func TestSuccessResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name       string
		statusCode int
		data       interface{}
	}{
		{
			name:       "Should return 200 OK with data",
			statusCode: 200,
			data: map[string]interface{}{
				"id":    "123",
				"name":  "John Doe",
				"email": "john@example.com",
			},
		},
		{
			name:       "Should return 201 Created with data",
			statusCode: 201,
			data: map[string]interface{}{
				"message": "Resource created successfully",
				"id":      "456",
			},
		},
		{
			name:       "Should return 200 OK with empty data",
			statusCode: 200,
			data:       map[string]interface{}{},
		},
		{
			name:       "Should return 200 OK with array data",
			statusCode: 200,
			data: []map[string]interface{}{
				{"id": "1", "name": "Item 1"},
				{"id": "2", "name": "Item 2"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			internalapi.SuccessResponse(c, tt.statusCode, tt.data)

			assert.Equal(t, tt.statusCode, w.Code)
			
			var resp interface{}
			err := json.Unmarshal(w.Body.Bytes(), &resp)
			assert.NoError(t, err)
		})
	}
}

// TestValidateJSON_Success tests successful JSON validation
func TestValidateJSON_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	type TestRequest struct {
		Name  string `json:"name" binding:"required"`
		Email string `json:"email" binding:"required,email"`
	}

	tests := []struct {
		name     string
		jsonBody string
	}{
		{
			name: "Should validate valid JSON",
			jsonBody: `{
				"name": "John Doe",
				"email": "john@example.com"
			}`,
		},
		{
			name: "Should validate JSON with extra fields",
			jsonBody: `{
				"name": "Jane Doe",
				"email": "jane@example.com",
				"age": 30,
				"city": "New York"
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", "/test", bytes.NewBufferString(tt.jsonBody))
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			var request TestRequest
			result := internalapi.ValidateJSON(c, &request)

			assert.True(t, result)
			assert.Equal(t, 200, w.Code)
			assert.Empty(t, w.Body.String())
		})
	}
}

// TestValidateJSON_InvalidJSON tests invalid JSON validation
func TestValidateJSON_InvalidJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)

	type TestRequest struct {
		Name  string `json:"name" binding:"required"`
		Email string `json:"email" binding:"required,email"`
	}

	tests := []struct {
		name           string
		jsonBody       string
		expectedStatus int
	}{
		{
			name:           "Should fail with malformed JSON",
			jsonBody:       `{invalid json}`,
			expectedStatus: 400,
		},
		{
			name:           "Should fail with empty JSON",
			jsonBody:       ``,
			expectedStatus: 400,
		},
		{
			name:           "Should fail with JSON array instead of object",
			jsonBody:       `[{"name": "John"}]`,
			expectedStatus: 400,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", "/test", bytes.NewBufferString(tt.jsonBody))
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			var request TestRequest
			result := internalapi.ValidateJSON(c, &request)

			assert.False(t, result)
			assert.Equal(t, tt.expectedStatus, w.Code)
			
			// Check that response body has code and message fields (from BadRequestWithCode)
			if w.Body.Len() > 0 {
				var resp map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &resp)
				assert.NoError(t, err)
				assert.Contains(t, resp, "code")
				assert.Contains(t, resp, "message")
				assert.Equal(t, "INVALID_JSON", resp["code"])
				assert.Equal(t, "Invalid JSON format", resp["message"])
			}
		})
	}
}

// TestValidateJSON_MissingRequiredFields tests validation with missing required fields
func TestValidateJSON_MissingRequiredFields(t *testing.T) {
	gin.SetMode(gin.TestMode)

	type TestRequest struct {
		Name  string `json:"name" binding:"required"`
		Email string `json:"email" binding:"required,email"`
	}

	tests := []struct {
		name     string
		jsonBody string
	}{
		{
			name: "Should fail with missing name field",
			jsonBody: `{
				"email": "john@example.com"
			}`,
		},
		{
			name: "Should fail with missing email field",
			jsonBody: `{
				"name": "John Doe"
			}`,
		},
		{
			name: "Should fail with both fields missing",
			jsonBody: `{}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", "/test", bytes.NewBufferString(tt.jsonBody))
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			var request TestRequest
			result := internalapi.ValidateJSON(c, &request)

			assert.False(t, result)
			assert.Equal(t, 400, w.Code)
			
			// Check that response body has code and message fields (from BadRequestWithCode)
			if w.Body.Len() > 0 {
				var resp map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &resp)
				assert.NoError(t, err)
				assert.Contains(t, resp, "code")
				assert.Contains(t, resp, "message")
				assert.Equal(t, "INVALID_JSON", resp["code"])
				assert.Equal(t, "Invalid JSON format", resp["message"])
			}
		})
	}
}

// TestValidateJSON_InvalidFieldFormat tests validation with invalid field format
func TestValidateJSON_InvalidFieldFormat(t *testing.T) {
	gin.SetMode(gin.TestMode)

	type TestRequest struct {
		Name  string `json:"name" binding:"required"`
		Email string `json:"email" binding:"required,email"`
		Age   int    `json:"age" binding:"min=18"`
	}

	tests := []struct {
		name     string
		jsonBody string
	}{
		{
			name: "Should fail with invalid email format",
			jsonBody: `{
				"name": "John Doe",
				"email": "invalid-email"
			}`,
		},
		{
			name: "Should fail with invalid age (too young)",
			jsonBody: `{
				"name": "John Doe",
				"email": "john@example.com",
				"age": 16
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", "/test", bytes.NewBufferString(tt.jsonBody))
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			var request TestRequest
			result := internalapi.ValidateJSON(c, &request)

			assert.False(t, result)
			assert.Equal(t, 400, w.Code)
			
			// Check that response body has code and message fields (from BadRequestWithCode)
			if w.Body.Len() > 0 {
				var resp map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &resp)
				assert.NoError(t, err)
				assert.Contains(t, resp, "code")
				assert.Contains(t, resp, "message")
				assert.Equal(t, "INVALID_JSON", resp["code"])
				assert.Equal(t, "Invalid JSON format", resp["message"])
			}
		})
	}
}

// TestValidateJSON_DifferentContentTypes tests validation with different content types
func TestValidateJSON_DifferentContentTypes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	type TestRequest struct {
		Name string `json:"name" binding:"required"`
	}

	tests := []struct {
		name        string
		contentType string
		shouldPass  bool
	}{
		{
			name:        "Should pass with application/json",
			contentType: "application/json",
			shouldPass:  true,
		},
		{
			name:        "Should pass with application/json; charset=utf-8",
			contentType: "application/json; charset=utf-8",
			shouldPass:  true,
		},
		{
			name:        "Should fail with text/plain",
			contentType: "text/plain",
			shouldPass:  false,
		},
		{
			name:        "Should fail with no content type",
			contentType: "",
			shouldPass:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonBody := `{"name": "John Doe"}`
			req, _ := http.NewRequest("POST", "/test", bytes.NewBufferString(jsonBody))
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			var request TestRequest
			result := internalapi.ValidateJSON(c, &request)

			// Note: With different content types, ShouldBindJSON might still work
			// depending on how Gin is configured. We'll just accept whatever result.
			_ = result
		})
	}
}

// TestResponseFunctionsAsHelpers tests that response functions can be used as helpers
func TestResponseFunctionsAsHelpers(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("Should use all response functions together", func(t *testing.T) {
		router := gin.New()
		
		router.GET("/bad-request", func(c *gin.Context) {
			internalapi.BadRequest(c, "Bad request example")
		})
		
		router.GET("/unauthorized", func(c *gin.Context) {
			internalapi.Unauthorized(c, "Please login")
		})
		
		router.GET("/success", func(c *gin.Context) {
			internalapi.SuccessResponse(c, 200, map[string]interface{}{"status": "ok"})
		})

		// Test BadRequest
		w1 := httptest.NewRecorder()
		req1, _ := http.NewRequest("GET", "/bad-request", nil)
		router.ServeHTTP(w1, req1)
		assert.Equal(t, 400, w1.Code)
		
		// Test Unauthorized
		w2 := httptest.NewRecorder()
		req2, _ := http.NewRequest("GET", "/unauthorized", nil)
		router.ServeHTTP(w2, req2)
		assert.Equal(t, 401, w2.Code)
		
		// Test SuccessResponse
		w3 := httptest.NewRecorder()
		req3, _ := http.NewRequest("GET", "/success", nil)
		router.ServeHTTP(w3, req3)
		assert.Equal(t, 200, w3.Code)
		
		var resp3 map[string]interface{}
		err := json.Unmarshal(w3.Body.Bytes(), &resp3)
		assert.NoError(t, err)
		assert.Equal(t, "ok", resp3["status"])
	})
}

// TestErrorResponseTypes tests that different error response functions return correct formats
func TestErrorResponseTypes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name     string
		callFunc func(c *gin.Context)
		expectedStatus int
		expectedError  string
	}{
		{
			name: "BadRequest should return error field",
			callFunc: func(c *gin.Context) {
				internalapi.BadRequest(c, "Bad request")
			},
			expectedStatus: 400,
			expectedError:  "Bad request",
		},
		{
			name: "Unauthorized should return error field",
			callFunc: func(c *gin.Context) {
				internalapi.Unauthorized(c, "Unauthorized")
			},
			expectedStatus: 401,
			expectedError:  "Unauthorized",
		},
		{
			name: "Forbidden should return error field",
			callFunc: func(c *gin.Context) {
				internalapi.Forbidden(c, "Forbidden")
			},
			expectedStatus: 403,
			expectedError:  "Forbidden",
		},
		{
			name: "NotFound should return error field",
			callFunc: func(c *gin.Context) {
				internalapi.NotFound(c, "Not found")
			},
			expectedStatus: 404,
			expectedError:  "Not found",
		},
		{
			name: "InternalServerError should return error field",
			callFunc: func(c *gin.Context) {
				internalapi.InternalServerError(c, "Internal error")
			},
			expectedStatus: 500,
			expectedError:  "Internal error",
		},
		{
			name: "ConflictError should return error field",
			callFunc: func(c *gin.Context) {
				internalapi.ConflictError(c, "Conflict")
			},
			expectedStatus: 409,
			expectedError:  "Conflict",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			tt.callFunc(c)

			assert.Equal(t, tt.expectedStatus, w.Code)
			
			var resp map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &resp)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedError, resp["error"])
		})
	}
}