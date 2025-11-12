package api

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/api"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/test/helpers"
)

func TestLogAuditAction(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	t.Run("log audit action success", func(t *testing.T) {
		details := map[string]interface{}{
			"ip": "192.168.1.1",
		}

		err := api.LogAuditAction(
			db,
			1,
			"user@example.com",
			"TEST_ACTION",
			"TEST_CATEGORY",
			"test_resource",
			"resource_123",
			"Test description",
			details,
			"192.168.1.100",
		)

		assert.NoError(t, err)

		var auditLog models.AuditLog
		result := db.Last(&auditLog)
		assert.NoError(t, result.Error)
		assert.Equal(t, uint(1), auditLog.UserID)
		assert.Equal(t, "user@example.com", auditLog.UserEmail)
		assert.Equal(t, "TEST_ACTION", auditLog.Action)
		assert.Equal(t, "TEST_CATEGORY", auditLog.Category)
		assert.Equal(t, "test_resource", auditLog.ResourceType)
		assert.Equal(t, "resource_123", auditLog.ResourceID)
		assert.Equal(t, "success", auditLog.Status)
		assert.Empty(t, auditLog.Error)
		assert.Equal(t, "192.168.1.100", auditLog.IPAddress)
	})

	t.Run("log audit action with nil details", func(t *testing.T) {
		err := api.LogAuditAction(
			db,
			2,
			"admin@example.com",
			"ACTION_2",
			"CATEGORY_2",
			"resource_type",
			"resource_id",
			"Description",
			nil,
			"10.0.0.1",
		)

		assert.NoError(t, err)

		var auditLog models.AuditLog
		db.Where("action = ?", "ACTION_2").Last(&auditLog)
		assert.Equal(t, "", auditLog.Details)
	})
}

func TestLogAuditActionWithError(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	t.Run("log audit action with error", func(t *testing.T) {
		details := map[string]interface{}{
			"error_code": "ERR_001",
		}

		err := api.LogAuditActionWithError(
			db,
			1,
			"user@example.com",
			"FAILED_ACTION",
			"CATEGORY",
			"resource_type",
			"resource_id",
			"Failed action",
			details,
			"192.168.1.100",
			"Database connection failed",
		)

		assert.NoError(t, err)

		var auditLog models.AuditLog
		result := db.Last(&auditLog)
		assert.NoError(t, result.Error)
		assert.Equal(t, "failure", auditLog.Status)
		assert.Equal(t, "Database connection failed", auditLog.Error)
	})
}

func TestLogAuthAction(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	t.Run("log successful auth action", func(t *testing.T) {
		err := api.LogAuthAction(
			db,
			1,
			"user@example.com",
			"LOGIN",
			"User login successful",
			true,
			"192.168.1.100",
		)

		assert.NoError(t, err)

		var auditLog models.AuditLog
		result := db.Last(&auditLog)
		assert.NoError(t, result.Error)
		assert.Equal(t, "LOGIN", auditLog.Action)
		assert.Equal(t, "AUTH", auditLog.Category)
		assert.Equal(t, "user", auditLog.ResourceType)
		assert.Equal(t, "user@example.com", auditLog.ResourceID)
		assert.Equal(t, "success", auditLog.Status)
	})

	t.Run("log failed auth action", func(t *testing.T) {
		err := api.LogAuthAction(
			db,
			0,
			"invalid@example.com",
			"LOGIN",
			"Invalid credentials",
			false,
			"192.168.1.200",
		)

		assert.NoError(t, err)

		var auditLog models.AuditLog
		db.Order("created_at DESC").First(&auditLog)
		assert.Equal(t, "failure", auditLog.Status)
	})
}

func TestLogBlocklistAction(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	t.Run("log blocklist action", func(t *testing.T) {
		err := api.LogBlocklistAction(
			db,
			1,
			"admin@example.com",
			"BLOCK",
			"192.168.1.50",
			"XSS",
			"24 hours",
			"192.168.1.100",
		)

		assert.NoError(t, err)

		var auditLog models.AuditLog
		result := db.Last(&auditLog)
		assert.NoError(t, result.Error)
		assert.Equal(t, "BLOCK_IP", auditLog.Action)
		assert.Equal(t, "BLOCKLIST", auditLog.Category)
		assert.Equal(t, "ip", auditLog.ResourceType)

		// Verify details
		var details map[string]interface{}
		json.Unmarshal([]byte(auditLog.Details), &details)
		assert.Equal(t, "192.168.1.50", details["ip"])
		assert.Equal(t, "XSS", details["threat_type"])
		assert.Equal(t, "24 hours", details["duration"])
	})

	t.Run("log unblock action", func(t *testing.T) {
		err := api.LogBlocklistAction(
			db,
			1,
			"admin@example.com",
			"UNBLOCK",
			"192.168.1.51",
			"SQL_INJECTION",
			"permanent",
			"192.168.1.100",
		)

		assert.NoError(t, err)

		var auditLog models.AuditLog
		db.Order("created_at DESC").First(&auditLog)
		assert.Equal(t, "UNBLOCK_IP", auditLog.Action)
	})
}

func TestLogWhitelistAction(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	t.Run("log whitelist add action", func(t *testing.T) {
		err := api.LogWhitelistAction(
			db,
			1,
			"admin@example.com",
			"ADD",
			"10.0.0.1",
			"Internal server",
			"192.168.1.100",
		)

		assert.NoError(t, err)

		var auditLog models.AuditLog
		result := db.Last(&auditLog)
		assert.NoError(t, result.Error)
		assert.Equal(t, "ADD_WHITELIST", auditLog.Action)
		assert.Equal(t, "WHITELIST", auditLog.Category)

		// Verify details
		var details map[string]interface{}
		json.Unmarshal([]byte(auditLog.Details), &details)
		assert.Equal(t, "10.0.0.1", details["ip"])
		assert.Equal(t, "Internal server", details["reason"])
	})

	t.Run("log whitelist remove action", func(t *testing.T) {
		err := api.LogWhitelistAction(
			db,
			1,
			"admin@example.com",
			"REMOVE",
			"10.0.0.2",
			"No longer needed",
			"192.168.1.100",
		)

		assert.NoError(t, err)

		var auditLog models.AuditLog
		db.Order("created_at DESC").First(&auditLog)
		assert.Equal(t, "REMOVE_WHITELIST", auditLog.Action)
	})
}

func TestLogFalsePositiveAction(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	t.Run("log false positive report", func(t *testing.T) {
		err := api.LogFalsePositiveAction(
			db,
			1,
			"user@example.com",
			"REPORT",
			"fp_123",
			"XSS",
			"192.168.1.10",
			"pending",
			"192.168.1.100",
		)

		assert.NoError(t, err)

		var auditLog models.AuditLog
		result := db.Last(&auditLog)
		assert.NoError(t, result.Error)
		assert.Equal(t, "REPORT_FALSE_POSITIVE", auditLog.Action)
		assert.Equal(t, "FALSE_POSITIVE", auditLog.Category)
		assert.Equal(t, "false_positive", auditLog.ResourceType)
		assert.Equal(t, "fp_123", auditLog.ResourceID)

		// Verify details
		var details map[string]interface{}
		json.Unmarshal([]byte(auditLog.Details), &details)
		assert.Equal(t, "XSS", details["threat_type"])
		assert.Equal(t, "192.168.1.10", details["client_ip"])
		assert.Equal(t, "pending", details["status"])
	})

	t.Run("log false positive update", func(t *testing.T) {
		err := api.LogFalsePositiveAction(
			db,
			2,
			"admin@example.com",
			"UPDATE",
			"fp_124",
			"SQL_INJECTION",
			"10.0.0.1",
			"reviewed",
			"192.168.1.100",
		)

		assert.NoError(t, err)

		var auditLog models.AuditLog
		db.Order("created_at DESC").First(&auditLog)
		assert.Equal(t, "UPDATE_FALSE_POSITIVE", auditLog.Action)
	})
}

func TestLogRuleAction(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	t.Run("log create rule action", func(t *testing.T) {
		details := map[string]interface{}{
			"pattern": ".*evil.*",
			"action":  "block",
		}

		err := api.LogRuleAction(
			db,
			1,
			"admin@example.com",
			"CREATE",
			"rule_123",
			"Custom XSS Rule",
			details,
			"192.168.1.100",
		)

		assert.NoError(t, err)

		var auditLog models.AuditLog
		result := db.Last(&auditLog)
		assert.NoError(t, result.Error)
		assert.Equal(t, "CREATE_RULE", auditLog.Action)
		assert.Equal(t, "RULE", auditLog.Category)
		assert.Equal(t, "rule", auditLog.ResourceType)
		assert.Equal(t, "rule_123", auditLog.ResourceID)

		// Verify details
		var logDetails map[string]interface{}
		json.Unmarshal([]byte(auditLog.Details), &logDetails)
		assert.Equal(t, ".*evil.*", logDetails["pattern"])
		assert.Equal(t, "block", logDetails["action"])
	})

	t.Run("log update rule action", func(t *testing.T) {
		err := api.LogRuleAction(
			db,
			1,
			"admin@example.com",
			"UPDATE",
			"rule_124",
			"Updated Rule",
			nil,
			"192.168.1.100",
		)

		assert.NoError(t, err)

		var auditLog models.AuditLog
		db.Order("created_at DESC").First(&auditLog)
		assert.Equal(t, "UPDATE_RULE", auditLog.Action)
	})

	t.Run("log delete rule action", func(t *testing.T) {
		err := api.LogRuleAction(
			db,
			1,
			"admin@example.com",
			"DELETE",
			"rule_125",
			"Deleted Rule",
			nil,
			"192.168.1.100",
		)

		assert.NoError(t, err)

		var auditLog models.AuditLog
		db.Order("created_at DESC").First(&auditLog)
		assert.Equal(t, "DELETE_RULE", auditLog.Action)
	})
}

func TestAuditLoggerTimestamp(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	beforeTime := time.Now()

	err := api.LogAuditAction(
		db,
		1,
		"user@example.com",
		"TIME_TEST",
		"CATEGORY",
		"resource",
		"id",
		"Test",
		nil,
		"192.168.1.1",
	)

	afterTime := time.Now()

	assert.NoError(t, err)

	var auditLog models.AuditLog
	db.Last(&auditLog)

	assert.True(t, auditLog.CreatedAt.After(beforeTime.Add(-time.Second)))
	assert.True(t, auditLog.CreatedAt.Before(afterTime.Add(time.Second)))
}

func TestAuditLoggerWithComplexDetails(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	complexDetails := map[string]interface{}{
		"string":  "value",
		"number":  42,
		"boolean": true,
		"array":   []string{"a", "b", "c"},
		"nested": map[string]interface{}{
			"key": "value",
		},
	}

	err := api.LogAuditAction(
		db,
		1,
		"user@example.com",
		"COMPLEX_TEST",
		"CATEGORY",
		"resource",
		"id",
		"Complex test",
		complexDetails,
		"192.168.1.1",
	)

	assert.NoError(t, err)

	var auditLog models.AuditLog
	db.Last(&auditLog)

	var retrievedDetails map[string]interface{}
	err = json.Unmarshal([]byte(auditLog.Details), &retrievedDetails)
	assert.NoError(t, err)
	assert.Equal(t, "value", retrievedDetails["string"])
	assert.Equal(t, float64(42), retrievedDetails["number"])
	assert.Equal(t, true, retrievedDetails["boolean"])
}
