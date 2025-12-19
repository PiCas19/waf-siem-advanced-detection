package repository

import (
	"context"
	"testing"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/logger"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/repository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func init() {
	logger.InitLogger("error", "stdout")
}

func setupWhitelistedIPDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&models.WhitelistedIP{})
	require.NoError(t, err)

	return db
}

func createTestWhitelistedIP(db *gorm.DB, ip, reason string) models.WhitelistedIP {
	whitelisted := models.WhitelistedIP{
		IPAddress: ip,
		Reason:    reason,
	}
	db.Create(&whitelisted)
	return whitelisted
}

func TestNewGormWhitelistedIPRepository(t *testing.T) {
	db := setupWhitelistedIPDB(t)
	repo := repository.NewGormWhitelistedIPRepository(db)
	assert.NotNil(t, repo)
}

func TestWhitelistedIPRepository_FindAll(t *testing.T) {
	db := setupWhitelistedIPDB(t)
	repo := repository.NewGormWhitelistedIPRepository(db)
	ctx := context.Background()

	createTestWhitelistedIP(db, "192.168.1.1", "Test 1")
	createTestWhitelistedIP(db, "192.168.1.2", "Test 2")

	whitelisted, err := repo.FindAll(ctx)
	assert.NoError(t, err)
	assert.Len(t, whitelisted, 2)
}

func TestWhitelistedIPRepository_FindByIP(t *testing.T) {
	db := setupWhitelistedIPDB(t)
	repo := repository.NewGormWhitelistedIPRepository(db)
	ctx := context.Background()

	createTestWhitelistedIP(db, "192.168.1.1", "Test")

	found, err := repo.FindByIP(ctx, "192.168.1.1")
	assert.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "192.168.1.1", found.IPAddress)
}

func TestWhitelistedIPRepository_FindByIP_NotFound(t *testing.T) {
	db := setupWhitelistedIPDB(t)
	repo := repository.NewGormWhitelistedIPRepository(db)
	ctx := context.Background()

	found, err := repo.FindByIP(ctx, "192.168.1.1")
	assert.NoError(t, err)
	assert.Nil(t, found)
}

func TestWhitelistedIPRepository_Create(t *testing.T) {
	db := setupWhitelistedIPDB(t)
	repo := repository.NewGormWhitelistedIPRepository(db)
	ctx := context.Background()

	whitelisted := &models.WhitelistedIP{
		IPAddress: "192.168.1.1",
		Reason:    "Test",
	}

	err := repo.Create(ctx, whitelisted)
	assert.NoError(t, err)
	assert.NotZero(t, whitelisted.ID)
}

func TestWhitelistedIPRepository_Update(t *testing.T) {
	db := setupWhitelistedIPDB(t)
	repo := repository.NewGormWhitelistedIPRepository(db)
	ctx := context.Background()

	whitelisted := createTestWhitelistedIP(db, "192.168.1.1", "Original")

	whitelisted.Reason = "Updated"

	err := repo.Update(ctx, &whitelisted)
	assert.NoError(t, err)

	updated, err := repo.FindByIP(ctx, "192.168.1.1")
	assert.NoError(t, err)
	assert.Equal(t, "Updated", updated.Reason)
}

func TestWhitelistedIPRepository_Delete(t *testing.T) {
	db := setupWhitelistedIPDB(t)
	repo := repository.NewGormWhitelistedIPRepository(db)
	ctx := context.Background()

	whitelisted := createTestWhitelistedIP(db, "192.168.1.1", "Test")

	err := repo.Delete(ctx, whitelisted.ID)
	assert.NoError(t, err)

	// Soft delete, so not found in normal query
	found, err := repo.FindByIP(ctx, "192.168.1.1")
	assert.NoError(t, err)
	assert.Nil(t, found)
}

func TestWhitelistedIPRepository_IsWhitelisted(t *testing.T) {
	db := setupWhitelistedIPDB(t)
	repo := repository.NewGormWhitelistedIPRepository(db)
	ctx := context.Background()

	createTestWhitelistedIP(db, "192.168.1.1", "Test")

	whitelisted, err := repo.IsWhitelisted(ctx, "192.168.1.1")
	assert.NoError(t, err)
	assert.True(t, whitelisted)

	whitelisted, err = repo.IsWhitelisted(ctx, "192.168.1.99")
	assert.NoError(t, err)
	assert.False(t, whitelisted)
}

func TestWhitelistedIPRepository_Count(t *testing.T) {
	db := setupWhitelistedIPDB(t)
	repo := repository.NewGormWhitelistedIPRepository(db)
	ctx := context.Background()

	createTestWhitelistedIP(db, "192.168.1.1", "Test 1")
	createTestWhitelistedIP(db, "192.168.1.2", "Test 2")

	count, err := repo.Count(ctx)
	assert.NoError(t, err)
	assert.Equal(t, int64(2), count)
}

func TestWhitelistedIPRepository_Restore(t *testing.T) {
	db := setupWhitelistedIPDB(t)
	repo := repository.NewGormWhitelistedIPRepository(db)
	ctx := context.Background()

	whitelisted := createTestWhitelistedIP(db, "192.168.1.1", "Test")

	// Delete it (soft delete)
	repo.Delete(ctx, whitelisted.ID)

	// Verify it's deleted
	found, err := repo.FindByIP(ctx, "192.168.1.1")
	assert.NoError(t, err)
	assert.Nil(t, found)

	// Restore it
	restored, err := repo.Restore(ctx, "192.168.1.1")
	assert.NoError(t, err)
	require.NotNil(t, restored)

	// Verify it's back
	found, err = repo.FindByIP(ctx, "192.168.1.1")
	assert.NoError(t, err)
	assert.NotNil(t, found)
}

func TestWhitelistedIPRepository_ExistsSoftDeleted(t *testing.T) {
	db := setupWhitelistedIPDB(t)
	repo := repository.NewGormWhitelistedIPRepository(db)
	ctx := context.Background()

	whitelisted := createTestWhitelistedIP(db, "192.168.1.1", "Test")

	// Should exist
	found, err := repo.ExistsSoftDeleted(ctx, "192.168.1.1")
	assert.NoError(t, err)
	require.NotNil(t, found)

	// Delete it
	repo.Delete(ctx, whitelisted.ID)

	// Should still exist in unscoped query
	found, err = repo.ExistsSoftDeleted(ctx, "192.168.1.1")
	assert.NoError(t, err)
	assert.NotNil(t, found)

	// Non-existent should return nil
	found, err = repo.ExistsSoftDeleted(ctx, "192.168.1.99")
	assert.NoError(t, err)
	assert.Nil(t, found)
}

func TestWhitelistedIPRepository_FindPaginated(t *testing.T) {
	db := setupWhitelistedIPDB(t)
	repo := repository.NewGormWhitelistedIPRepository(db)
	ctx := context.Background()

	for i := 0; i < 15; i++ {
		createTestWhitelistedIP(db, "192.168.1."+string(rune('0'+i)), "Test")
	}

	// First page
	whitelisted, total, err := repo.FindPaginated(ctx, 0, 10)
	assert.NoError(t, err)
	assert.Len(t, whitelisted, 10)
	assert.Equal(t, int64(15), total)

	// Second page
	whitelisted, total, err = repo.FindPaginated(ctx, 10, 10)
	assert.NoError(t, err)
	assert.Len(t, whitelisted, 5)
	assert.Equal(t, int64(15), total)
}
