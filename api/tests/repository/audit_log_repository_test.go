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

func setupAuditLogDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&models.AuditLog{})
	require.NoError(t, err)

	return db
}

func createTestAuditLog(db *gorm.DB, userID uint, action, status string) models.AuditLog {
	auditLog := models.AuditLog{
		UserID:    userID,
		Action:    action,
		Status:    status,
		IPAddress: "192.168.1.1",
		Details:   "Test details",
		CreatedAt: time.Now(),
	}
	db.Create(&auditLog)
	return auditLog
}

func TestNewGormAuditLogRepository(t *testing.T) {
	db := setupAuditLogDB(t)
	repo := repository.NewGormAuditLogRepository(db)
	assert.NotNil(t, repo)
}

func TestAuditLogRepository_FindAll(t *testing.T) {
	db := setupAuditLogDB(t)
	repo := repository.NewGormAuditLogRepository(db)
	ctx := context.Background()

	createTestAuditLog(db, 1, "login", "success")
	createTestAuditLog(db, 2, "logout", "success")
	createTestAuditLog(db, 1, "update_profile", "success")

	logs, err := repo.FindAll(ctx)
	assert.NoError(t, err)
	assert.Len(t, logs, 3)
}

func TestAuditLogRepository_FindByUser(t *testing.T) {
	db := setupAuditLogDB(t)
	repo := repository.NewGormAuditLogRepository(db)
	ctx := context.Background()

	createTestAuditLog(db, 1, "login", "success")
	createTestAuditLog(db, 1, "logout", "success")
	createTestAuditLog(db, 2, "login", "success")

	logs, err := repo.FindByUser(ctx, 1)
	assert.NoError(t, err)
	assert.Len(t, logs, 2)

	for _, log := range logs {
		assert.Equal(t, uint(1), log.UserID)
	}
}

func TestAuditLogRepository_FindByAction(t *testing.T) {
	db := setupAuditLogDB(t)
	repo := repository.NewGormAuditLogRepository(db)
	ctx := context.Background()

	createTestAuditLog(db, 1, "login", "success")
	createTestAuditLog(db, 2, "login", "success")
	createTestAuditLog(db, 1, "logout", "success")

	logs, err := repo.FindByAction(ctx, "login")
	assert.NoError(t, err)
	assert.Len(t, logs, 2)

	for _, log := range logs {
		assert.Equal(t, "login", log.Action)
	}
}

func TestAuditLogRepository_FindRecent(t *testing.T) {
	db := setupAuditLogDB(t)
	repo := repository.NewGormAuditLogRepository(db)
	ctx := context.Background()

	// Create 10 logs
	for i := 0; i < 10; i++ {
		createTestAuditLog(db, 1, "action", "success")
		time.Sleep(1 * time.Millisecond)
	}

	logs, err := repo.FindRecent(ctx, 5)
	assert.NoError(t, err)
	assert.Len(t, logs, 5)
}

func TestAuditLogRepository_Create(t *testing.T) {
	db := setupAuditLogDB(t)
	repo := repository.NewGormAuditLogRepository(db)
	ctx := context.Background()

	auditLog := &models.AuditLog{
		UserID:    1,
		Action:    "login",
		Status:    "success",
		IPAddress: "192.168.1.1",
		Details:   "User logged in",
	}

	err := repo.Create(ctx, auditLog)
	assert.NoError(t, err)
	assert.NotZero(t, auditLog.ID)
}

func TestAuditLogRepository_Count(t *testing.T) {
	db := setupAuditLogDB(t)
	repo := repository.NewGormAuditLogRepository(db)
	ctx := context.Background()

	createTestAuditLog(db, 1, "login", "success")
	createTestAuditLog(db, 2, "logout", "success")
	createTestAuditLog(db, 1, "update", "failure")

	count, err := repo.Count(ctx)
	assert.NoError(t, err)
	assert.Equal(t, int64(3), count)
}

func TestAuditLogRepository_CountByStatus(t *testing.T) {
	db := setupAuditLogDB(t)
	repo := repository.NewGormAuditLogRepository(db)
	ctx := context.Background()

	createTestAuditLog(db, 1, "login", "success")
	createTestAuditLog(db, 2, "login", "success")
	createTestAuditLog(db, 1, "update", "failure")

	successCount, err := repo.CountByStatus(ctx, "success")
	assert.NoError(t, err)
	assert.Equal(t, int64(2), successCount)

	failureCount, err := repo.CountByStatus(ctx, "failure")
	assert.NoError(t, err)
	assert.Equal(t, int64(1), failureCount)
}

func TestAuditLogRepository_FindPaginated(t *testing.T) {
	db := setupAuditLogDB(t)
	repo := repository.NewGormAuditLogRepository(db)
	ctx := context.Background()

	// Create 15 logs
	for i := 0; i < 15; i++ {
		createTestAuditLog(db, 1, "action", "success")
		time.Sleep(1 * time.Millisecond)
	}

	// First page
	logs, total, err := repo.FindPaginated(ctx, 0, 10)
	assert.NoError(t, err)
	assert.Len(t, logs, 10)
	assert.Equal(t, int64(15), total)

	// Second page
	logs, total, err = repo.FindPaginated(ctx, 10, 10)
	assert.NoError(t, err)
	assert.Len(t, logs, 5)
	assert.Equal(t, int64(15), total)
}

func TestAuditLogRepository_GetActionBreakdown(t *testing.T) {
	db := setupAuditLogDB(t)
	repo := repository.NewGormAuditLogRepository(db)
	ctx := context.Background()

	createTestAuditLog(db, 1, "login", "success")
	createTestAuditLog(db, 1, "login", "success")
	createTestAuditLog(db, 2, "logout", "success")
	createTestAuditLog(db, 1, "update_profile", "success")
	createTestAuditLog(db, 2, "update_profile", "success")
	createTestAuditLog(db, 3, "delete", "success")

	breakdown, err := repo.GetActionBreakdown(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, breakdown)
	assert.Equal(t, int64(2), breakdown["login"])
	assert.Equal(t, int64(1), breakdown["logout"])
	assert.Equal(t, int64(2), breakdown["update_profile"])
	assert.Equal(t, int64(1), breakdown["delete"])
}

func TestAuditLogRepository_GetActionBreakdown_Empty(t *testing.T) {
	db := setupAuditLogDB(t)
	repo := repository.NewGormAuditLogRepository(db)
	ctx := context.Background()

	breakdown, err := repo.GetActionBreakdown(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, breakdown)
	assert.Empty(t, breakdown)
}

func TestAuditLogRepository_FindByUser_NoResults(t *testing.T) {
	db := setupAuditLogDB(t)
	repo := repository.NewGormAuditLogRepository(db)
	ctx := context.Background()

	createTestAuditLog(db, 1, "login", "success")

	logs, err := repo.FindByUser(ctx, 999)
	assert.NoError(t, err)
	assert.Empty(t, logs)
}

func TestAuditLogRepository_FindByAction_NoResults(t *testing.T) {
	db := setupAuditLogDB(t)
	repo := repository.NewGormAuditLogRepository(db)
	ctx := context.Background()

	createTestAuditLog(db, 1, "login", "success")

	logs, err := repo.FindByAction(ctx, "nonexistent_action")
	assert.NoError(t, err)
	assert.Empty(t, logs)
}
