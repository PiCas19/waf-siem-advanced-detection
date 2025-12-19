package repository

import (
	"context"
	"testing"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/repository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&models.Log{})
	require.NoError(t, err)

	return db
}

func createTestLog(db *gorm.DB, clientIP, threatType, description string, blocked bool) models.Log {
	log := models.Log{
		ClientIP:    clientIP,
		ThreatType:  threatType,
		Description: description,
		Blocked:     blocked,
		Severity:    "high",
		Method:      "GET",
		URL:         "/test",
		UserAgent:   "test-agent",
		CreatedAt:   time.Now(),
	}
	db.Create(&log)
	return log
}

func TestNewGormLogRepository(t *testing.T) {
	db := setupTestDB(t)
	repo := repository.NewGormLogRepository(db)
	assert.NotNil(t, repo)
}

func TestLogRepository_FindAll(t *testing.T) {
	db := setupTestDB(t)
	repo := repository.NewGormLogRepository(db)
	ctx := context.Background()

	// Create test logs
	createTestLog(db, "192.168.1.1", "SQL Injection", "Test SQL", false)
	createTestLog(db, "192.168.1.2", "XSS", "Test XSS", true)
	createTestLog(db, "192.168.1.3", "CSRF", "Test CSRF", false)

	logs, err := repo.FindAll(ctx)
	assert.NoError(t, err)
	assert.Len(t, logs, 3)
}

func TestLogRepository_FindByID(t *testing.T) {
	db := setupTestDB(t)
	repo := repository.NewGormLogRepository(db)
	ctx := context.Background()

	// Create test log
	created := createTestLog(db, "192.168.1.1", "SQL Injection", "Test", false)

	// Find by ID
	found, err := repo.FindByID(ctx, created.ID)
	assert.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, created.ID, found.ID)
	assert.Equal(t, "192.168.1.1", found.ClientIP)
}

func TestLogRepository_FindByID_NotFound(t *testing.T) {
	db := setupTestDB(t)
	repo := repository.NewGormLogRepository(db)
	ctx := context.Background()

	found, err := repo.FindByID(ctx, 9999)
	assert.NoError(t, err)
	assert.Nil(t, found)
}

func TestLogRepository_FindByIP(t *testing.T) {
	db := setupTestDB(t)
	repo := repository.NewGormLogRepository(db)
	ctx := context.Background()

	// Create logs with same IP
	createTestLog(db, "192.168.1.1", "SQL Injection", "Test 1", false)
	createTestLog(db, "192.168.1.1", "XSS", "Test 2", true)
	createTestLog(db, "192.168.1.2", "CSRF", "Test 3", false)

	logs, err := repo.FindByIP(ctx, "192.168.1.1")
	assert.NoError(t, err)
	assert.Len(t, logs, 2)
	
	for _, log := range logs {
		assert.Equal(t, "192.168.1.1", log.ClientIP)
	}
}

func TestLogRepository_FindBlocked(t *testing.T) {
	db := setupTestDB(t)
	repo := repository.NewGormLogRepository(db)
	ctx := context.Background()

	createTestLog(db, "192.168.1.1", "SQL Injection", "Test 1", false)
	createTestLog(db, "192.168.1.2", "XSS", "Test 2", true)
	createTestLog(db, "192.168.1.3", "CSRF", "Test 3", true)

	logs, err := repo.FindBlocked(ctx)
	assert.NoError(t, err)
	assert.Len(t, logs, 2)
	
	for _, log := range logs {
		assert.True(t, log.Blocked)
	}
}

func TestLogRepository_FindByThreatType(t *testing.T) {
	db := setupTestDB(t)
	repo := repository.NewGormLogRepository(db)
	ctx := context.Background()

	createTestLog(db, "192.168.1.1", "SQL Injection", "Test 1", false)
	createTestLog(db, "192.168.1.2", "SQL Injection", "Test 2", true)
	createTestLog(db, "192.168.1.3", "XSS", "Test 3", false)

	logs, err := repo.FindByThreatType(ctx, "SQL Injection")
	assert.NoError(t, err)
	assert.Len(t, logs, 2)
	
	for _, log := range logs {
		assert.Equal(t, "SQL Injection", log.ThreatType)
	}
}

func TestLogRepository_FindRecent(t *testing.T) {
	db := setupTestDB(t)
	repo := repository.NewGormLogRepository(db)
	ctx := context.Background()

	// Create 10 logs
	for i := 0; i < 10; i++ {
		createTestLog(db, "192.168.1.1", "Test", "Test", false)
		time.Sleep(1 * time.Millisecond)
	}

	logs, err := repo.FindRecent(ctx, 5)
	assert.NoError(t, err)
	assert.Len(t, logs, 5)
}

func TestLogRepository_Count(t *testing.T) {
	db := setupTestDB(t)
	repo := repository.NewGormLogRepository(db)
	ctx := context.Background()

	createTestLog(db, "192.168.1.1", "SQL Injection", "Test 1", false)
	createTestLog(db, "192.168.1.2", "XSS", "Test 2", true)
	createTestLog(db, "192.168.1.3", "CSRF", "Test 3", false)

	count, err := repo.Count(ctx)
	assert.NoError(t, err)
	assert.Equal(t, int64(3), count)
}

func TestLogRepository_CountBlocked(t *testing.T) {
	db := setupTestDB(t)
	repo := repository.NewGormLogRepository(db)
	ctx := context.Background()

	createTestLog(db, "192.168.1.1", "SQL Injection", "Test 1", false)
	createTestLog(db, "192.168.1.2", "XSS", "Test 2", true)
	createTestLog(db, "192.168.1.3", "CSRF", "Test 3", true)

	count, err := repo.CountBlocked(ctx)
	assert.NoError(t, err)
	assert.Equal(t, int64(2), count)
}

func TestLogRepository_Create(t *testing.T) {
	db := setupTestDB(t)
	repo := repository.NewGormLogRepository(db)
	ctx := context.Background()

	log := &models.Log{
		ClientIP:    "192.168.1.1",
		ThreatType:  "SQL Injection",
		Description: "Test",
		Blocked:     false,
		Severity:    "high",
		Method:      "POST",
		URL:         "/api/test",
		UserAgent:   "test-agent",
	}

	err := repo.Create(ctx, log)
	assert.NoError(t, err)
	assert.NotZero(t, log.ID)
}

func TestLogRepository_Update(t *testing.T) {
	db := setupTestDB(t)
	repo := repository.NewGormLogRepository(db)
	ctx := context.Background()

	log := createTestLog(db, "192.168.1.1", "SQL Injection", "Original", false)

	// Update log
	log.Description = "Updated"
	log.Blocked = true

	err := repo.Update(ctx, &log)
	assert.NoError(t, err)

	// Verify update
	updated, err := repo.FindByID(ctx, log.ID)
	assert.NoError(t, err)
	assert.Equal(t, "Updated", updated.Description)
	assert.True(t, updated.Blocked)
}

func TestLogRepository_Delete(t *testing.T) {
	db := setupTestDB(t)
	repo := repository.NewGormLogRepository(db)
	ctx := context.Background()

	log := createTestLog(db, "192.168.1.1", "SQL Injection", "Test", false)

	err := repo.Delete(ctx, log.ID)
	assert.NoError(t, err)

	// Verify deletion
	found, err := repo.FindByID(ctx, log.ID)
	assert.NoError(t, err)
	assert.Nil(t, found)
}

func TestLogRepository_UpdateByIPAndDescription(t *testing.T) {
	db := setupTestDB(t)
	repo := repository.NewGormLogRepository(db)
	ctx := context.Background()

	createTestLog(db, "192.168.1.1", "SQL Injection", "Test Attack", false)
	createTestLog(db, "192.168.1.1", "XSS", "Test Attack", false)
	createTestLog(db, "192.168.1.2", "SQL Injection", "Different", false)

	updates := map[string]interface{}{
		"blocked": true,
	}

	err := repo.UpdateByIPAndDescription(ctx, "192.168.1.1", "Test Attack", updates)
	assert.NoError(t, err)

	// Verify updates
	logs, _ := repo.FindByIP(ctx, "192.168.1.1")
	for _, log := range logs {
		if log.Description == "Test Attack" {
			assert.True(t, log.Blocked)
		}
	}
}

func TestLogRepository_UpdateDetectedByIPAndDescription(t *testing.T) {
	db := setupTestDB(t)
	repo := repository.NewGormLogRepository(db)
	ctx := context.Background()

	createTestLog(db, "192.168.1.1", "SQL Injection", "Test Attack", false)
	createTestLog(db, "192.168.1.1", "SQL Injection", "Test Attack", true)

	updates := map[string]interface{}{
		"blocked": true,
	}

	err := repo.UpdateDetectedByIPAndDescription(ctx, "192.168.1.1", "Test Attack", updates)
	assert.NoError(t, err)

	// Only the non-blocked log should be updated
	logs, _ := repo.FindByIP(ctx, "192.168.1.1")
	assert.Len(t, logs, 2)
	
	blockedCount := 0
	for _, log := range logs {
		if log.Blocked {
			blockedCount++
		}
	}
	assert.Equal(t, 2, blockedCount)
}

func TestLogRepository_FindPaginated(t *testing.T) {
	db := setupTestDB(t)
	repo := repository.NewGormLogRepository(db)
	ctx := context.Background()

	// Create 20 logs
	for i := 0; i < 20; i++ {
		createTestLog(db, "192.168.1.1", "Test", "Test", false)
		time.Sleep(1 * time.Millisecond)
	}

	// First page
	logs, total, err := repo.FindPaginated(ctx, 0, 10)
	assert.NoError(t, err)
	assert.Len(t, logs, 10)
	assert.Equal(t, int64(20), total)

	// Second page
	logs, total, err = repo.FindPaginated(ctx, 10, 10)
	assert.NoError(t, err)
	assert.Len(t, logs, 10)
	assert.Equal(t, int64(20), total)

	// Third page (empty)
	logs, total, err = repo.FindPaginated(ctx, 20, 10)
	assert.NoError(t, err)
	assert.Len(t, logs, 0)
	assert.Equal(t, int64(20), total)
}

func TestLogRepository_DeleteManualBlockLog(t *testing.T) {
	db := setupTestDB(t)
	repo := repository.NewGormLogRepository(db)
	ctx := context.Background()

	// Create manual block log
	log := models.Log{
		ClientIP:    "192.168.1.1",
		ThreatType:  "SQL Injection",
		Description: "Test Attack",
		Blocked:     true,
		BlockedBy:   "manual",
		Method:      "MANUAL_BLOCK",
		Severity:    "high",
		URL:         "/test",
		UserAgent:   "test",
	}
	db.Create(&log)

	// Create another log that shouldn't be deleted
	createTestLog(db, "192.168.1.1", "SQL Injection", "Test Attack", true)

	err := repo.DeleteManualBlockLog(ctx, "192.168.1.1", "Test Attack")
	assert.NoError(t, err)

	// Verify only manual block log was deleted
	logs, _ := repo.FindByIP(ctx, "192.168.1.1")
	assert.Len(t, logs, 1)
	assert.NotEqual(t, "MANUAL_BLOCK", logs[0].Method)
}
