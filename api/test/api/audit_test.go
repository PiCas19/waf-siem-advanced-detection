package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	internalapi "github.com/PiCas19/waf-siem-advanced-detection/api/internal/api"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
)

// TestLogAudit_Success tests successful audit log creation
func TestLogAudit_Success(t *testing.T) {
	db, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	db.AutoMigrate(&models.AuditLog{})

	router := gin.New()
	router.GET("/test", func(c *gin.Context) {
		c.Set("user_id", uint(1))
		c.Set("user_email", "admin@example.com")

		details := map[string]interface{}{
			"field1": "value1",
			"count":  42,
		}

		err := internalapi.LogAudit(
			db,
			c,
			"user.created",
			"USER_MANAGEMENT",
			"New user created",
			"user",
			"user_123",
			details,
			"success",
			"",
		)

		assert.NoError(t, err)
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:8080"
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	var auditLog models.AuditLog
	result := db.First(&auditLog)
	assert.NoError(t, result.Error)
	assert.Equal(t, uint(1), auditLog.UserID)
	assert.Equal(t, "admin@example.com", auditLog.UserEmail)
	assert.Equal(t, "user.created", auditLog.Action)
	assert.Equal(t, "success", auditLog.Status)
}

// TestLogAudit_WithoutUserContext tests audit log without user context
func TestLogAudit_WithoutUserContext(t *testing.T) {
	db, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	db.AutoMigrate(&models.AuditLog{})

	router := gin.New()
	router.GET("/test", func(c *gin.Context) {
		// No user_id or user_email in context

		err := internalapi.LogAudit(
			db,
			c,
			"anonymous.action",
			"SYSTEM",
			"Anonymous action",
			"resource",
			"res_1",
			nil,
			"success",
			"",
		)

		assert.NoError(t, err)
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.1:8080"
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	var auditLog models.AuditLog
	result := db.First(&auditLog)
	assert.NoError(t, result.Error)
	assert.Equal(t, uint(0), auditLog.UserID)
	assert.Equal(t, "", auditLog.UserEmail)
}

// TestLogAudit_WithInvalidUserIDType tests audit log with invalid user ID type in context
func TestLogAudit_WithInvalidUserIDType(t *testing.T) {
	db, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	db.AutoMigrate(&models.AuditLog{})

	router := gin.New()
	router.GET("/test", func(c *gin.Context) {
		c.Set("user_id", "invalid_string") // Wrong type
		c.Set("user_email", "user@example.com")

		err := internalapi.LogAudit(
			db,
			c,
			"user.action",
			"ACTION",
			"Test action",
			"resource",
			"res_1",
			nil,
			"success",
			"",
		)

		assert.NoError(t, err)
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:8080"
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	var auditLog models.AuditLog
	result := db.First(&auditLog)
	assert.NoError(t, result.Error)
	assert.Equal(t, uint(0), auditLog.UserID) // Should default to 0
}

// TestLogAudit_WithInvalidEmailType tests audit log with invalid email type
func TestLogAudit_WithInvalidEmailType(t *testing.T) {
	db, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	db.AutoMigrate(&models.AuditLog{})

	router := gin.New()
	router.GET("/test", func(c *gin.Context) {
		c.Set("user_id", uint(2))
		c.Set("user_email", 12345) // Wrong type

		err := internalapi.LogAudit(
			db,
			c,
			"user.action",
			"ACTION",
			"Test action",
			"resource",
			"res_2",
			nil,
			"success",
			"",
		)

		assert.NoError(t, err)
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.2:8080"
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	var auditLog models.AuditLog
	result := db.First(&auditLog)
	assert.NoError(t, result.Error)
	assert.Equal(t, uint(2), auditLog.UserID)
	assert.Equal(t, "", auditLog.UserEmail) // Should default to empty
}

// TestLogAudit_WithNilDetails tests audit log with nil details
func TestLogAudit_WithNilDetails(t *testing.T) {
	db, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	db.AutoMigrate(&models.AuditLog{})

	router := gin.New()
	router.GET("/test", func(c *gin.Context) {
		c.Set("user_id", uint(3))
		c.Set("user_email", "user@example.com")

		err := internalapi.LogAudit(
			db,
			c,
			"simple.action",
			"SIMPLE",
			"Action without details",
			"resource",
			"res_3",
			nil,
			"success",
			"",
		)

		assert.NoError(t, err)
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.3:8080"
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	var auditLog models.AuditLog
	result := db.First(&auditLog)
	assert.NoError(t, result.Error)
	assert.Empty(t, auditLog.Details)
}

// TestLogAudit_WithComplexDetails tests audit log with complex nested details
func TestLogAudit_WithComplexDetails(t *testing.T) {
	db, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	db.AutoMigrate(&models.AuditLog{})

	router := gin.New()
	router.GET("/test", func(c *gin.Context) {
		c.Set("user_id", uint(4))
		c.Set("user_email", "admin@example.com")

		details := map[string]interface{}{
			"user": map[string]interface{}{
				"name":  "John Doe",
				"email": "john@example.com",
			},
			"permissions": []string{"read", "write", "admin"},
			"timestamp":   "2024-01-01T12:00:00Z",
		}

		err := internalapi.LogAudit(
			db,
			c,
			"user.updated",
			"USER_MANAGEMENT",
			"User permissions updated",
			"user",
			"user_456",
			details,
			"success",
			"",
		)

		assert.NoError(t, err)
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.4:8080"
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	var auditLog models.AuditLog
	result := db.First(&auditLog)
	assert.NoError(t, result.Error)
	assert.NotEmpty(t, auditLog.Details)
}

// TestLogAudit_WithError tests audit log with error status
func TestLogAudit_WithError(t *testing.T) {
	db, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	db.AutoMigrate(&models.AuditLog{})

	router := gin.New()
	router.GET("/test", func(c *gin.Context) {
		c.Set("user_id", uint(5))
		c.Set("user_email", "user@example.com")

		err := internalapi.LogAudit(
			db,
			c,
			"action.failed",
			"ERROR",
			"Action failed",
			"resource",
			"res_5",
			nil,
			"failure",
			"permission denied",
		)

		assert.NoError(t, err)
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.5:8080"
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	var auditLog models.AuditLog
	result := db.First(&auditLog)
	assert.NoError(t, result.Error)
	assert.Equal(t, "failure", auditLog.Status)
	assert.Equal(t, "permission denied", auditLog.Error)
}

// TestLogAuditSimple_Success tests simple audit log creation
func TestLogAuditSimple_Success(t *testing.T) {
	db, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	db.AutoMigrate(&models.AuditLog{})

	router := gin.New()
	router.GET("/test", func(c *gin.Context) {
		c.Set("user_id", uint(6))
		c.Set("user_email", "admin@example.com")

		err := internalapi.LogAuditSimple(
			db,
			c,
			"simple.action",
			"SIMPLE",
			"Simple audit action",
			"success",
		)

		assert.NoError(t, err)
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.6:8080"
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	var auditLog models.AuditLog
	result := db.First(&auditLog)
	assert.NoError(t, result.Error)
	assert.Equal(t, "simple.action", auditLog.Action)
	assert.Equal(t, "SIMPLE", auditLog.Category)
	assert.Equal(t, "", auditLog.ResourceType)
	assert.Equal(t, "", auditLog.ResourceID)
}

// TestLogAuditSimple_WithoutUser tests simple audit log without user context
func TestLogAuditSimple_WithoutUser(t *testing.T) {
	db, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	db.AutoMigrate(&models.AuditLog{})

	router := gin.New()
	router.GET("/test", func(c *gin.Context) {
		// No user context

		err := internalapi.LogAuditSimple(
			db,
			c,
			"anonymous.action",
			"ANONYMOUS",
			"Anonymous action",
			"success",
		)

		assert.NoError(t, err)
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "10.0.0.1:8080"
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	var auditLog models.AuditLog
	result := db.First(&auditLog)
	assert.NoError(t, result.Error)
	assert.Equal(t, uint(0), auditLog.UserID)
}

// TestLogAuditWithError_Success tests error audit log creation
func TestLogAuditWithError_Success(t *testing.T) {
	db, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	db.AutoMigrate(&models.AuditLog{})

	router := gin.New()
	router.GET("/test", func(c *gin.Context) {
		c.Set("user_id", uint(7))
		c.Set("user_email", "user@example.com")

		details := map[string]interface{}{
			"reason": "validation failed",
		}

		err := internalapi.LogAuditWithError(
			db,
			c,
			"user.create",
			"USER",
			"Failed to create user",
			"user",
			"user_7",
			details,
			"email already exists",
		)

		assert.NoError(t, err)
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.7:8080"
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	var auditLog models.AuditLog
	result := db.First(&auditLog)
	assert.NoError(t, result.Error)
	assert.Equal(t, "failure", auditLog.Status)
	assert.Equal(t, "email already exists", auditLog.Error)
}

// TestLogAuditWithError_WithNilDetails tests error audit log with nil details
func TestLogAuditWithError_WithNilDetails(t *testing.T) {
	db, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	db.AutoMigrate(&models.AuditLog{})

	router := gin.New()
	router.GET("/test", func(c *gin.Context) {
		c.Set("user_id", uint(8))
		c.Set("user_email", "user@example.com")

		err := internalapi.LogAuditWithError(
			db,
			c,
			"operation.failed",
			"OPERATION",
			"Operation failed",
			"operation",
			"op_1",
			nil,
			"timeout",
		)

		assert.NoError(t, err)
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.8:8080"
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	var auditLog models.AuditLog
	result := db.First(&auditLog)
	assert.NoError(t, result.Error)
	assert.Equal(t, "failure", auditLog.Status)
	assert.Equal(t, "timeout", auditLog.Error)
	assert.Empty(t, auditLog.Details)
}

// TestLogAuditSuccess_Success tests successful audit log creation
func TestLogAuditSuccess_Success(t *testing.T) {
	db, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	db.AutoMigrate(&models.AuditLog{})

	router := gin.New()
	router.GET("/test", func(c *gin.Context) {
		c.Set("user_id", uint(9))
		c.Set("user_email", "admin@example.com")

		details := map[string]interface{}{
			"created_at": "2024-01-01T12:00:00Z",
		}

		err := internalapi.LogAuditSuccess(
			db,
			c,
			"user.created",
			"USER",
			"User successfully created",
			"user",
			"user_9",
			details,
		)

		assert.NoError(t, err)
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.9:8080"
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	var auditLog models.AuditLog
	result := db.First(&auditLog)
	assert.NoError(t, result.Error)
	assert.Equal(t, "success", auditLog.Status)
	assert.Empty(t, auditLog.Error)
}

// TestLogAuditSuccess_WithoutDetails tests successful audit log without details
func TestLogAuditSuccess_WithoutDetails(t *testing.T) {
	db, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	db.AutoMigrate(&models.AuditLog{})

	router := gin.New()
	router.GET("/test", func(c *gin.Context) {
		c.Set("user_id", uint(10))
		c.Set("user_email", "user@example.com")

		err := internalapi.LogAuditSuccess(
			db,
			c,
			"report.generated",
			"REPORTING",
			"Report generated successfully",
			"report",
			"report_1",
			nil,
		)

		assert.NoError(t, err)
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.10:8080"
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	var auditLog models.AuditLog
	result := db.First(&auditLog)
	assert.NoError(t, result.Error)
	assert.Equal(t, "report.generated", auditLog.Action)
	assert.Equal(t, "success", auditLog.Status)
}

// TestLogAudit_ClientIPExtraction tests client IP extraction
func TestLogAudit_ClientIPExtraction(t *testing.T) {
	db, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	db.AutoMigrate(&models.AuditLog{})

	router := gin.New()
	router.GET("/test", func(c *gin.Context) {
		c.Set("user_id", uint(11))

		err := internalapi.LogAudit(
			db,
			c,
			"test.action",
			"TEST",
			"Test IP extraction",
			"resource",
			"res_11",
			nil,
			"success",
			"",
		)

		assert.NoError(t, err)
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "203.0.113.45:9876"
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	var auditLog models.AuditLog
	result := db.First(&auditLog)
	assert.NoError(t, result.Error)
	// Client IP should be extracted from request
	assert.NotEmpty(t, auditLog.IPAddress)
}

// TestLogAudit_WithUnmarshalableDetails tests audit log with details that cannot be marshaled
func TestLogAudit_WithUnmarshalableDetails(t *testing.T) {
	db, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	db.AutoMigrate(&models.AuditLog{})

	router := gin.New()
	router.GET("/test", func(c *gin.Context) {
		c.Set("user_id", uint(13))
		c.Set("user_email", "admin@example.com")

		// Create details with circular reference (unmarshalable)
		details := make(map[string]interface{})
		details["self"] = details // Circular reference

		err := internalapi.LogAudit(
			db,
			c,
			"test.action",
			"TEST",
			"Test unmarshalable details",
			"resource",
			"res_13",
			details,
			"success",
			"",
		)

		// Should not error - the function handles marshal errors gracefully
		assert.NoError(t, err)
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.13:8080"
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	var auditLog models.AuditLog
	result := db.First(&auditLog)
	assert.NoError(t, result.Error)
	// Details should be empty when marshaling fails
	assert.Empty(t, auditLog.Details)
}

// TestLogAudit_HandlesEmptyString tests audit log with empty strings
func TestLogAudit_HandlesEmptyString(t *testing.T) {
	db, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	db.AutoMigrate(&models.AuditLog{})

	router := gin.New()
	router.GET("/test", func(c *gin.Context) {
		c.Set("user_id", uint(14))
		c.Set("user_email", "")

		err := internalapi.LogAudit(
			db,
			c,
			"",
			"",
			"",
			"",
			"",
			nil,
			"",
			"",
		)

		assert.NoError(t, err)
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.14:8080"
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	var auditLog models.AuditLog
	result := db.First(&auditLog)
	assert.NoError(t, result.Error)
	assert.Equal(t, uint(14), auditLog.UserID)
}

// Note: The exact error logging path (lines 56-59) for db.Create failures cannot be
// easily unit tested because logger.Log is a global singleton. However, all function
// entry points are covered (88.9% coverage on LogAudit covers 8/9 statements).

// TestLogAudit_MultipleActions tests multiple sequential audit logs
func TestLogAudit_MultipleActions(t *testing.T) {
	db, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	db.AutoMigrate(&models.AuditLog{})

	router := gin.New()
	router.GET("/test", func(c *gin.Context) {
		c.Set("user_id", uint(12))
		c.Set("user_email", "user@example.com")

		// Log multiple actions
		internalapi.LogAuditSuccess(db, c, "action1", "CAT1", "First action", "res", "res1", nil)
		internalapi.LogAuditSuccess(db, c, "action2", "CAT2", "Second action", "res", "res2", nil)
		internalapi.LogAuditWithError(db, c, "action3", "CAT3", "Third action", "res", "res3", nil, "error")

		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.12:8080"
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	var count int64
	db.Model(&models.AuditLog{}).Count(&count)
	assert.Equal(t, int64(3), count)

	var successCount int64
	db.Model(&models.AuditLog{}).Where("status = ?", "success").Count(&successCount)
	assert.Equal(t, int64(2), successCount)
}
