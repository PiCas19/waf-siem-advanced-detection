package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	internalapi "github.com/PiCas19/waf-siem-advanced-detection/api/internal/api"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
)

// setupTestDB creates an in-memory SQLite database for testing
func setupTestDB() *gorm.DB {
	db, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	db.AutoMigrate(&models.AuditLog{})
	return db
}

// TestLogAuditAction_Success tests successful audit log creation
func TestLogAuditAction_Success(t *testing.T) {
	db := setupTestDB()

	details := map[string]interface{}{
		"field1": "value1",
		"field2": 123,
	}

	err := internalapi.LogAuditAction(
		db,
		uint(1),
		"admin@example.com",
		"user.created",
		"USER_MANAGEMENT",
		"user",
		"user_123",
		"New user created",
		details,
		"192.168.1.1",
	)

	assert.NoError(t, err)

	// Verify the audit log was created
	var auditLog models.AuditLog
	result := db.First(&auditLog)
	assert.NoError(t, result.Error)
	assert.Equal(t, uint(1), auditLog.UserID)
	assert.Equal(t, "admin@example.com", auditLog.UserEmail)
	assert.Equal(t, "user.created", auditLog.Action)
	assert.Equal(t, "USER_MANAGEMENT", auditLog.Category)
	assert.Equal(t, "success", auditLog.Status)
	assert.NotEmpty(t, auditLog.Details)
}

// TestLogAuditAction_WithNilDetails tests audit log creation with nil details
func TestLogAuditAction_WithNilDetails(t *testing.T) {
	db := setupTestDB()

	err := internalapi.LogAuditAction(
		db,
		uint(2),
		"user@example.com",
		"user.login",
		"AUTH",
		"user",
		"user_2",
		"User logged in",
		nil,
		"10.0.0.1",
	)

	assert.NoError(t, err)

	var auditLog models.AuditLog
	result := db.First(&auditLog)
	assert.NoError(t, result.Error)
	assert.Equal(t, "user.login", auditLog.Action)
	assert.Empty(t, auditLog.Details)
}

// TestLogAuditAction_WithEmptyDetails tests audit log creation with empty details
func TestLogAuditAction_WithEmptyDetails(t *testing.T) {
	db := setupTestDB()

	err := internalapi.LogAuditAction(
		db,
		uint(3),
		"viewer@example.com",
		"report.viewed",
		"REPORTING",
		"report",
		"report_1",
		"Report viewed",
		map[string]interface{}{},
		"172.16.0.1",
	)

	assert.NoError(t, err)

	var auditLog models.AuditLog
	result := db.First(&auditLog)
	assert.NoError(t, result.Error)
	assert.Equal(t, "report.viewed", auditLog.Action)
}

// TestLogAuditAction_WithComplexDetails tests audit log with complex nested details
func TestLogAuditAction_WithComplexDetails(t *testing.T) {
	db := setupTestDB()

	details := map[string]interface{}{
		"user": map[string]interface{}{
			"name":  "John Doe",
			"email": "john@example.com",
		},
		"roles": []string{"admin", "user"},
		"count": 42,
	}

	err := internalapi.LogAuditAction(
		db,
		uint(4),
		"admin@example.com",
		"user.updated",
		"USER_MANAGEMENT",
		"user",
		"user_4",
		"User roles updated",
		details,
		"192.168.1.100",
	)

	assert.NoError(t, err)

	var auditLog models.AuditLog
	result := db.First(&auditLog)
	assert.NoError(t, result.Error)
	assert.NotEmpty(t, auditLog.Details)
}

// TestLogAuditActionWithError_Success tests successful error audit log creation
func TestLogAuditActionWithError_Success(t *testing.T) {
	db := setupTestDB()

	details := map[string]interface{}{
		"reason": "insufficient permissions",
	}

	err := internalapi.LogAuditActionWithError(
		db,
		uint(5),
		"user@example.com",
		"admin.access",
		"AUTH",
		"admin",
		"admin_panel",
		"Unauthorized admin access attempt",
		details,
		"10.0.0.50",
		"insufficient permissions",
	)

	assert.NoError(t, err)

	var auditLog models.AuditLog
	result := db.First(&auditLog)
	assert.NoError(t, result.Error)
	assert.Equal(t, "failure", auditLog.Status)
	assert.Equal(t, "insufficient permissions", auditLog.Error)
}

// TestLogAuditActionWithError_WithNilDetails tests error log with nil details
func TestLogAuditActionWithError_WithNilDetails(t *testing.T) {
	db := setupTestDB()

	err := internalapi.LogAuditActionWithError(
		db,
		uint(6),
		"admin@example.com",
		"invalid.operation",
		"SYSTEM",
		"operation",
		"op_1",
		"Invalid operation attempted",
		nil,
		"192.168.0.1",
		"validation error",
	)

	assert.NoError(t, err)

	var auditLog models.AuditLog
	result := db.First(&auditLog)
	assert.NoError(t, result.Error)
	assert.Equal(t, "failure", auditLog.Status)
	assert.Equal(t, "validation error", auditLog.Error)
	assert.Empty(t, auditLog.Details)
}

// TestLogAuthAction_Success tests successful authentication audit log
func TestLogAuthAction_Success(t *testing.T) {
	db := setupTestDB()

	err := internalapi.LogAuthAction(
		db,
		uint(7),
		"user@example.com",
		"login",
		"User successfully logged in",
		true,
		"192.168.1.50",
	)

	assert.NoError(t, err)

	var auditLog models.AuditLog
	result := db.First(&auditLog)
	assert.NoError(t, result.Error)
	assert.Equal(t, "login", auditLog.Action)
	assert.Equal(t, "AUTH", auditLog.Category)
	assert.Equal(t, "success", auditLog.Status)
	assert.Equal(t, "user", auditLog.ResourceType)
}

// TestLogAuthAction_Failure tests failed authentication audit log
func TestLogAuthAction_Failure(t *testing.T) {
	db := setupTestDB()

	err := internalapi.LogAuthAction(
		db,
		uint(8),
		"attacker@example.com",
		"login",
		"Login failed - invalid credentials",
		false,
		"10.0.0.100",
	)

	assert.NoError(t, err)

	var auditLog models.AuditLog
	result := db.First(&auditLog)
	assert.NoError(t, result.Error)
	assert.Equal(t, "login", auditLog.Action)
	assert.Equal(t, "AUTH", auditLog.Category)
	assert.Equal(t, "failure", auditLog.Status)
}

// TestLogBlocklistAction_AddIP tests blocklist add IP audit log
func TestLogBlocklistAction_AddIP(t *testing.T) {
	db := setupTestDB()

	err := internalapi.LogBlocklistAction(
		db,
		uint(9),
		"admin@example.com",
		"add",
		"203.0.113.1",
		"malware",
		"7d",
		"192.168.1.1",
	)

	assert.NoError(t, err)

	var auditLog models.AuditLog
	result := db.First(&auditLog)
	assert.NoError(t, result.Error)
	assert.Equal(t, "add", auditLog.Action)
	assert.Equal(t, "BLOCKLIST", auditLog.Category)
	assert.Equal(t, "ip", auditLog.ResourceType)
	assert.Equal(t, "203.0.113.1", auditLog.ResourceID)
}

// TestLogBlocklistAction_RemoveIP tests blocklist remove IP audit log
func TestLogBlocklistAction_RemoveIP(t *testing.T) {
	db := setupTestDB()

	err := internalapi.LogBlocklistAction(
		db,
		uint(10),
		"admin@example.com",
		"remove",
		"198.51.100.1",
		"suspicious",
		"",
		"192.168.1.2",
	)

	assert.NoError(t, err)

	var auditLog models.AuditLog
	result := db.First(&auditLog)
	assert.NoError(t, result.Error)
	assert.Equal(t, "remove", auditLog.Action)
}

// TestLogWhitelistAction_Add tests whitelist add IP audit log
func TestLogWhitelistAction_Add(t *testing.T) {
	db := setupTestDB()

	err := internalapi.LogWhitelistAction(
		db,
		uint(11),
		"admin@example.com",
		"add",
		"192.0.2.1",
		"partner network",
		"192.168.1.3",
	)

	assert.NoError(t, err)

	var auditLog models.AuditLog
	result := db.First(&auditLog)
	assert.NoError(t, result.Error)
	assert.Equal(t, "add", auditLog.Action)
	assert.Equal(t, "WHITELIST", auditLog.Category)
	assert.Equal(t, "ip", auditLog.ResourceType)
	assert.Equal(t, "192.0.2.1", auditLog.ResourceID)
}

// TestLogWhitelistAction_Remove tests whitelist remove IP audit log
func TestLogWhitelistAction_Remove(t *testing.T) {
	db := setupTestDB()

	err := internalapi.LogWhitelistAction(
		db,
		uint(12),
		"admin@example.com",
		"remove",
		"192.0.2.2",
		"contract ended",
		"192.168.1.4",
	)

	assert.NoError(t, err)

	var auditLog models.AuditLog
	result := db.First(&auditLog)
	assert.NoError(t, result.Error)
	assert.Equal(t, "remove", auditLog.Action)
	assert.Equal(t, "WHITELIST", auditLog.Category)
}

// TestLogFalsePositiveAction_Report tests false positive report audit log
func TestLogFalsePositiveAction_Report(t *testing.T) {
	db := setupTestDB()

	err := internalapi.LogFalsePositiveAction(
		db,
		uint(13),
		"analyst@example.com",
		"report",
		"fp_123",
		"bot",
		"203.0.113.50",
		"open",
		"192.168.1.5",
	)

	assert.NoError(t, err)

	var auditLog models.AuditLog
	result := db.First(&auditLog)
	assert.NoError(t, result.Error)
	assert.Equal(t, "report", auditLog.Action)
	assert.Equal(t, "FALSE_POSITIVE", auditLog.Category)
	assert.Equal(t, "false_positive", auditLog.ResourceType)
	assert.Equal(t, "fp_123", auditLog.ResourceID)
}

// TestLogFalsePositiveAction_Verify tests false positive verify audit log
func TestLogFalsePositiveAction_Verify(t *testing.T) {
	db := setupTestDB()

	err := internalapi.LogFalsePositiveAction(
		db,
		uint(14),
		"security@example.com",
		"verify",
		"fp_456",
		"scanner",
		"198.51.100.50",
		"resolved",
		"192.168.1.6",
	)

	assert.NoError(t, err)

	var auditLog models.AuditLog
	result := db.First(&auditLog)
	assert.NoError(t, result.Error)
	assert.Equal(t, "verify", auditLog.Action)
	assert.Equal(t, "FALSE_POSITIVE", auditLog.Category)
}

// TestLogRuleAction_Create tests rule create audit log
func TestLogRuleAction_Create(t *testing.T) {
	db := setupTestDB()

	details := map[string]interface{}{
		"pattern":  "SELECT.*FROM.*WHERE",
		"severity": "high",
	}

	err := internalapi.LogRuleAction(
		db,
		uint(15),
		"admin@example.com",
		"create",
		"rule_1",
		"SQL Injection Detection",
		details,
		"192.168.1.7",
	)

	assert.NoError(t, err)

	var auditLog models.AuditLog
	result := db.First(&auditLog)
	assert.NoError(t, result.Error)
	assert.Equal(t, "create", auditLog.Action)
	assert.Equal(t, "RULE", auditLog.Category)
	assert.Equal(t, "rule", auditLog.ResourceType)
	assert.Equal(t, "rule_1", auditLog.ResourceID)
}

// TestLogRuleAction_Update tests rule update audit log
func TestLogRuleAction_Update(t *testing.T) {
	db := setupTestDB()

	details := map[string]interface{}{
		"old_severity": "medium",
		"new_severity": "high",
	}

	err := internalapi.LogRuleAction(
		db,
		uint(16),
		"admin@example.com",
		"update",
		"rule_2",
		"XSS Detection",
		details,
		"192.168.1.8",
	)

	assert.NoError(t, err)

	var auditLog models.AuditLog
	result := db.First(&auditLog)
	assert.NoError(t, result.Error)
	assert.Equal(t, "update", auditLog.Action)
}

// TestLogRuleAction_Delete tests rule delete audit log
func TestLogRuleAction_Delete(t *testing.T) {
	db := setupTestDB()

	err := internalapi.LogRuleAction(
		db,
		uint(17),
		"admin@example.com",
		"delete",
		"rule_3",
		"Deprecated Rule",
		nil,
		"192.168.1.9",
	)

	assert.NoError(t, err)

	var auditLog models.AuditLog
	result := db.First(&auditLog)
	assert.NoError(t, result.Error)
	assert.Equal(t, "delete", auditLog.Action)
	assert.Equal(t, "RULE", auditLog.Category)
}

// TestLogRuleAction_WithNilDetails tests rule action with nil details
func TestLogRuleAction_WithNilDetails(t *testing.T) {
	db := setupTestDB()

	err := internalapi.LogRuleAction(
		db,
		uint(18),
		"admin@example.com",
		"enable",
		"rule_4",
		"Rate Limiting Rule",
		nil,
		"192.168.1.10",
	)

	assert.NoError(t, err)

	var auditLog models.AuditLog
	result := db.First(&auditLog)
	assert.NoError(t, result.Error)
	assert.Equal(t, "enable", auditLog.Action)
	assert.Empty(t, auditLog.Details)
}

// TestLogAuditAction_MultipleEntries tests creating multiple audit logs
func TestLogAuditAction_MultipleEntries(t *testing.T) {
	db := setupTestDB()

	for i := 1; i <= 5; i++ {
		err := internalapi.LogAuditAction(
			db,
			uint(i),
			"user"+string(rune(i))+"@example.com",
			"action_"+string(rune(i)),
			"CATEGORY",
			"resource",
			"resource_"+string(rune(i)),
			"Description "+string(rune(i)),
			nil,
			"192.168.1."+string(rune(i)),
		)
		assert.NoError(t, err)
	}

	var count int64
	db.Model(&models.AuditLog{}).Count(&count)
	assert.Equal(t, int64(5), count)
}

// TestLogAuthAction_MultipleAttempts tests multiple authentication attempts
func TestLogAuthAction_MultipleAttempts(t *testing.T) {
	db := setupTestDB()

	// Successful login
	err := internalapi.LogAuthAction(
		db,
		uint(19),
		"user@example.com",
		"login",
		"Successful login",
		true,
		"192.168.1.20",
	)
	assert.NoError(t, err)

	// Failed login attempt
	err = internalapi.LogAuthAction(
		db,
		uint(0),
		"attacker@example.com",
		"login",
		"Failed login attempt",
		false,
		"10.0.0.200",
	)
	assert.NoError(t, err)

	// Logout
	err = internalapi.LogAuthAction(
		db,
		uint(19),
		"user@example.com",
		"logout",
		"User logged out",
		true,
		"192.168.1.20",
	)
	assert.NoError(t, err)

	var count int64
	db.Model(&models.AuditLog{}).Count(&count)
	assert.Equal(t, int64(3), count)

	var successCount int64
	db.Model(&models.AuditLog{}).Where("status = ?", "success").Count(&successCount)
	assert.Equal(t, int64(2), successCount)
}
