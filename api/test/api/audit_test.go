package api

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/api"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/test/helpers"
)

func TestLogAudit(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/test", nil)
	c.Request.RemoteAddr = "192.168.1.1"
	c.Set("user_id", uint(1))
	c.Set("user_email", "user@example.com")

	t.Run("log audit with all details", func(t *testing.T) {
		details := map[string]interface{}{
			"ip":   "192.168.1.2",
			"port": 8080,
		}

		err := api.LogAudit(
			db,
			c,
			"TEST_ACTION",
			"TEST_CATEGORY",
			"Test description",
			"test_resource",
			"resource_123",
			details,
			"success",
			"",
		)

		assert.NoError(t, err)

		var auditLog models.AuditLog
		result := db.Last(&auditLog)
		assert.NoError(t, result.Error)
		assert.Equal(t, "TEST_ACTION", auditLog.Action)
		assert.Equal(t, "TEST_CATEGORY", auditLog.Category)
		assert.Equal(t, "Test description", auditLog.Description)
		assert.Equal(t, "test_resource", auditLog.ResourceType)
		assert.Equal(t, "resource_123", auditLog.ResourceID)
		assert.Equal(t, "success", auditLog.Status)
		assert.NotEmpty(t, auditLog.Details)
	})

	t.Run("log audit with nil details", func(t *testing.T) {
		err := api.LogAudit(
			db,
			c,
			"TEST_ACTION2",
			"TEST_CATEGORY",
			"Test description 2",
			"",
			"",
			nil,
			"success",
			"",
		)

		assert.NoError(t, err)

		var auditLog models.AuditLog
		result := db.Where("action = ?", "TEST_ACTION2").Last(&auditLog)
		assert.NoError(t, result.Error)
		assert.Equal(t, "", auditLog.Details)
	})

	t.Run("log audit with error", func(t *testing.T) {
		err := api.LogAudit(
			db,
			c,
			"TEST_FAILURE",
			"TEST_CATEGORY",
			"Failed action",
			"test_resource",
			"resource_456",
			nil,
			"failure",
			"Database error occurred",
		)

		assert.NoError(t, err)

		var auditLog models.AuditLog
		result := db.Where("action = ?", "TEST_FAILURE").Last(&auditLog)
		assert.NoError(t, result.Error)
		assert.Equal(t, "failure", auditLog.Status)
		assert.Equal(t, "Database error occurred", auditLog.Error)
	})

	t.Run("log audit captures user info", func(t *testing.T) {
		err := api.LogAudit(
			db,
			c,
			"USER_TEST",
			"TEST_CATEGORY",
			"User test",
			"",
			"",
			nil,
			"success",
			"",
		)

		assert.NoError(t, err)

		var auditLog models.AuditLog
		result := db.Where("action = ?", "USER_TEST").Last(&auditLog)
		assert.NoError(t, result.Error)
		assert.Equal(t, uint(1), auditLog.UserID)
		assert.Equal(t, "user@example.com", auditLog.UserEmail)
	})

	t.Run("log audit captures ip address", func(t *testing.T) {
		err := api.LogAudit(
			db,
			c,
			"IP_TEST",
			"TEST_CATEGORY",
			"IP test",
			"",
			"",
			nil,
			"success",
			"",
		)

		assert.NoError(t, err)

		var auditLog models.AuditLog
		result := db.Where("action = ?", "IP_TEST").Last(&auditLog)
		assert.NoError(t, result.Error)
		assert.NotEmpty(t, auditLog.IPAddress)
	})
}

func TestLogAuditSimple(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/test", nil)
	c.Request.RemoteAddr = "192.168.1.1"
	c.Set("user_id", uint(1))
	c.Set("user_email", "user@example.com")

	t.Run("log audit simple", func(t *testing.T) {
		err := api.LogAuditSimple(
			db,
			c,
			"SIMPLE_ACTION",
			"TEST_CATEGORY",
			"Simple test",
			"success",
		)

		assert.NoError(t, err)

		var auditLog models.AuditLog
		result := db.Last(&auditLog)
		assert.NoError(t, result.Error)
		assert.Equal(t, "SIMPLE_ACTION", auditLog.Action)
		assert.Equal(t, "TEST_CATEGORY", auditLog.Category)
		assert.Equal(t, "Simple test", auditLog.Description)
		assert.Equal(t, "", auditLog.ResourceType)
		assert.Equal(t, "", auditLog.ResourceID)
		assert.Equal(t, "success", auditLog.Status)
		assert.Equal(t, "", auditLog.Error)
	})
}

func TestLogAuditWithError(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/test", nil)
	c.Request.RemoteAddr = "192.168.1.1"
	c.Set("user_id", uint(1))
	c.Set("user_email", "user@example.com")

	t.Run("log audit with error", func(t *testing.T) {
		details := map[string]interface{}{
			"error_code": "ERR_001",
		}

		err := api.LogAuditWithError(
			db,
			c,
			"ACTION_WITH_ERROR",
			"TEST_CATEGORY",
			"Action failed",
			"resource_type",
			"resource_id",
			details,
			"Something went wrong",
		)

		assert.NoError(t, err)

		var auditLog models.AuditLog
		result := db.Last(&auditLog)
		assert.NoError(t, result.Error)
		assert.Equal(t, "ACTION_WITH_ERROR", auditLog.Action)
		assert.Equal(t, "failure", auditLog.Status)
		assert.Equal(t, "Something went wrong", auditLog.Error)
	})
}

func TestLogAuditSuccess(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/test", nil)
	c.Request.RemoteAddr = "192.168.1.1"
	c.Set("user_id", uint(1))
	c.Set("user_email", "user@example.com")

	t.Run("log audit success", func(t *testing.T) {
		details := map[string]interface{}{
			"result": "success",
		}

		err := api.LogAuditSuccess(
			db,
			c,
			"SUCCESS_ACTION",
			"TEST_CATEGORY",
			"Action succeeded",
			"resource_type",
			"resource_id",
			details,
		)

		assert.NoError(t, err)

		var auditLog models.AuditLog
		result := db.Last(&auditLog)
		assert.NoError(t, result.Error)
		assert.Equal(t, "SUCCESS_ACTION", auditLog.Action)
		assert.Equal(t, "success", auditLog.Status)
		assert.Equal(t, "", auditLog.Error)
	})
}

func TestLogAuditWithoutUserContext(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/test", nil)
	c.Request.RemoteAddr = "192.168.1.1"
	// No user context set

	t.Run("log audit without user context", func(t *testing.T) {
		err := api.LogAudit(
			db,
			c,
			"NO_USER_ACTION",
			"TEST_CATEGORY",
			"No user action",
			"",
			"",
			nil,
			"success",
			"",
		)

		assert.NoError(t, err)

		var auditLog models.AuditLog
		result := db.Last(&auditLog)
		assert.NoError(t, result.Error)
		assert.Equal(t, uint(0), auditLog.UserID)
		assert.Equal(t, "", auditLog.UserEmail)
	})
}
