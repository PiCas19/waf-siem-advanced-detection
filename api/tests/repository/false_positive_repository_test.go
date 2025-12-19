package repository

import (
	"context"
	"testing"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/repository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupFalsePositiveDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&models.FalsePositive{})
	require.NoError(t, err)

	return db
}

func createTestFalsePositive(db *gorm.DB, clientIP, threatType, description, status string) models.FalsePositive {
	fp := models.FalsePositive{
		ClientIP:    clientIP,
		ThreatType:  threatType,
		Description: description,
		Status:      status,
		Method:      "GET",
		URL:         "/test",
		UserAgent:   "test-agent",
	}
	db.Create(&fp)
	return fp
}

func TestNewGormFalsePositiveRepository(t *testing.T) {
	db := setupFalsePositiveDB(t)
	repo := repository.NewGormFalsePositiveRepository(db)
	assert.NotNil(t, repo)
}

func TestFalsePositiveRepository_FindAll(t *testing.T) {
	db := setupFalsePositiveDB(t)
	repo := repository.NewGormFalsePositiveRepository(db)
	ctx := context.Background()

	createTestFalsePositive(db, "192.168.1.1", "xss", "Test FP 1", "pending")
	createTestFalsePositive(db, "192.168.1.2", "sql_injection", "Test FP 2", "reviewed")
	createTestFalsePositive(db, "192.168.1.3", "lfi", "Test FP 3", "pending")

	fps, err := repo.FindAll(ctx)
	assert.NoError(t, err)
	assert.Len(t, fps, 3)
}

func TestFalsePositiveRepository_FindByID(t *testing.T) {
	db := setupFalsePositiveDB(t)
	repo := repository.NewGormFalsePositiveRepository(db)
	ctx := context.Background()

	created := createTestFalsePositive(db, "192.168.1.1", "xss", "Test", "pending")

	found, err := repo.FindByID(ctx, created.ID)
	assert.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, created.ID, found.ID)
	assert.Equal(t, "192.168.1.1", found.ClientIP)
}

func TestFalsePositiveRepository_FindByID_NotFound(t *testing.T) {
	db := setupFalsePositiveDB(t)
	repo := repository.NewGormFalsePositiveRepository(db)
	ctx := context.Background()

	found, err := repo.FindByID(ctx, 9999)
	assert.NoError(t, err)
	assert.Nil(t, found)
}

func TestFalsePositiveRepository_FindByIP(t *testing.T) {
	db := setupFalsePositiveDB(t)
	repo := repository.NewGormFalsePositiveRepository(db)
	ctx := context.Background()

	createTestFalsePositive(db, "192.168.1.1", "xss", "Test 1", "pending")
	createTestFalsePositive(db, "192.168.1.1", "sql_injection", "Test 2", "reviewed")
	createTestFalsePositive(db, "192.168.1.2", "lfi", "Test 3", "pending")

	fps, err := repo.FindByIP(ctx, "192.168.1.1")
	assert.NoError(t, err)
	assert.Len(t, fps, 2)

	for _, fp := range fps {
		assert.Equal(t, "192.168.1.1", fp.ClientIP)
	}
}

func TestFalsePositiveRepository_FindUnresolved(t *testing.T) {
	db := setupFalsePositiveDB(t)
	repo := repository.NewGormFalsePositiveRepository(db)
	ctx := context.Background()

	createTestFalsePositive(db, "192.168.1.1", "xss", "Unresolved 1", "pending")
	createTestFalsePositive(db, "192.168.1.2", "sql_injection", "Resolved", "reviewed")
	createTestFalsePositive(db, "192.168.1.3", "lfi", "Unresolved 2", "pending")

	fps, err := repo.FindUnresolved(ctx)
	assert.NoError(t, err)
	assert.Len(t, fps, 2)

	for _, fp := range fps {
		assert.Equal(t, "pending", fp.Status)
	}
}

func TestFalsePositiveRepository_Create(t *testing.T) {
	db := setupFalsePositiveDB(t)
	repo := repository.NewGormFalsePositiveRepository(db)
	ctx := context.Background()

	fp := &models.FalsePositive{
		ClientIP:    "192.168.1.1",
		ThreatType:  "xss",
		Description: "Test false positive",
		Status:      "pending",
		Method:      "GET",
		URL:         "/test",
		UserAgent:   "test-agent",
	}

	err := repo.Create(ctx, fp)
	assert.NoError(t, err)
	assert.NotZero(t, fp.ID)
}

func TestFalsePositiveRepository_Update(t *testing.T) {
	db := setupFalsePositiveDB(t)
	repo := repository.NewGormFalsePositiveRepository(db)
	ctx := context.Background()

	fp := createTestFalsePositive(db, "192.168.1.1", "xss", "Original", "pending")

	fp.Description = "Updated"
	fp.Status = "reviewed"

	err := repo.Update(ctx, &fp)
	assert.NoError(t, err)

	updated, err := repo.FindByID(ctx, fp.ID)
	assert.NoError(t, err)
	assert.Equal(t, "Updated", updated.Description)
	assert.Equal(t, "reviewed", updated.Status)
}

func TestFalsePositiveRepository_Delete(t *testing.T) {
	db := setupFalsePositiveDB(t)
	repo := repository.NewGormFalsePositiveRepository(db)
	ctx := context.Background()

	fp := createTestFalsePositive(db, "192.168.1.1", "xss", "Test", "pending")

	err := repo.Delete(ctx, fp.ID)
	assert.NoError(t, err)

	found, err := repo.FindByID(ctx, fp.ID)
	assert.NoError(t, err)
	assert.Nil(t, found)
}

func TestFalsePositiveRepository_Count(t *testing.T) {
	db := setupFalsePositiveDB(t)
	repo := repository.NewGormFalsePositiveRepository(db)
	ctx := context.Background()

	createTestFalsePositive(db, "192.168.1.1", "xss", "Test 1", "pending")
	createTestFalsePositive(db, "192.168.1.2", "sql_injection", "Test 2", "reviewed")
	createTestFalsePositive(db, "192.168.1.3", "lfi", "Test 3", "pending")

	count, err := repo.Count(ctx)
	assert.NoError(t, err)
	assert.Equal(t, int64(3), count)
}

func TestFalsePositiveRepository_CountUnresolved(t *testing.T) {
	db := setupFalsePositiveDB(t)
	repo := repository.NewGormFalsePositiveRepository(db)
	ctx := context.Background()

	createTestFalsePositive(db, "192.168.1.1", "xss", "Unresolved 1", "pending")
	createTestFalsePositive(db, "192.168.1.2", "sql_injection", "Resolved", "reviewed")
	createTestFalsePositive(db, "192.168.1.3", "lfi", "Unresolved 2", "pending")

	count, err := repo.CountUnresolved(ctx)
	assert.NoError(t, err)
	assert.Equal(t, int64(2), count)
}

func TestFalsePositiveRepository_FindPaginated(t *testing.T) {
	db := setupFalsePositiveDB(t)
	repo := repository.NewGormFalsePositiveRepository(db)
	ctx := context.Background()

	// Create 15 false positives
	for i := 0; i < 15; i++ {
		createTestFalsePositive(db, "192.168.1.1", "xss", "Test", "pending")
	}

	// First page
	fps, total, err := repo.FindPaginated(ctx, 0, 10)
	assert.NoError(t, err)
	assert.Len(t, fps, 10)
	assert.Equal(t, int64(15), total)

	// Second page
	fps, total, err = repo.FindPaginated(ctx, 10, 10)
	assert.NoError(t, err)
	assert.Len(t, fps, 5)
	assert.Equal(t, int64(15), total)
}

func TestFalsePositiveRepository_FindByIP_NoResults(t *testing.T) {
	db := setupFalsePositiveDB(t)
	repo := repository.NewGormFalsePositiveRepository(db)
	ctx := context.Background()

	createTestFalsePositive(db, "192.168.1.1", "xss", "Test", "pending")

	fps, err := repo.FindByIP(ctx, "192.168.1.99")
	assert.NoError(t, err)
	assert.Empty(t, fps)
}

func TestFalsePositiveRepository_FindUnresolved_AllResolved(t *testing.T) {
	db := setupFalsePositiveDB(t)
	repo := repository.NewGormFalsePositiveRepository(db)
	ctx := context.Background()

	createTestFalsePositive(db, "192.168.1.1", "xss", "Resolved 1", "reviewed")
	createTestFalsePositive(db, "192.168.1.2", "sql_injection", "Resolved 2", "reviewed")

	fps, err := repo.FindUnresolved(ctx)
	assert.NoError(t, err)
	assert.Empty(t, fps)
}
