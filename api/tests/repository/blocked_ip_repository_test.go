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

func setupBlockedIPDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&models.BlockedIP{})
	require.NoError(t, err)

	return db
}

func createTestBlockedIP(db *gorm.DB, ip, description string, permanent bool, expiresAt *time.Time) models.BlockedIP {
	blockedIP := models.BlockedIP{
		IPAddress:   ip,
		Description: description,
		Permanent:   permanent,
		ExpiresAt:   expiresAt,
	}
	db.Create(&blockedIP)
	return blockedIP
}

func TestNewGormBlockedIPRepository(t *testing.T) {
	db := setupBlockedIPDB(t)
	repo := repository.NewGormBlockedIPRepository(db)
	assert.NotNil(t, repo)
}

func TestBlockedIPRepository_FindAll(t *testing.T) {
	db := setupBlockedIPDB(t)
	repo := repository.NewGormBlockedIPRepository(db)
	ctx := context.Background()

	createTestBlockedIP(db, "192.168.1.1", "Test 1", true, nil)
	futureTime := time.Now().Add(24 * time.Hour)
	createTestBlockedIP(db, "192.168.1.2", "Test 2", false, &futureTime)
	createTestBlockedIP(db, "192.168.1.3", "Test 3", true, nil)

	blocked, err := repo.FindAll(ctx)
	assert.NoError(t, err)
	assert.Len(t, blocked, 3)
}

func TestBlockedIPRepository_FindByIP(t *testing.T) {
	db := setupBlockedIPDB(t)
	repo := repository.NewGormBlockedIPRepository(db)
	ctx := context.Background()

	createTestBlockedIP(db, "192.168.1.1", "Test", true, nil)

	found, err := repo.FindByIP(ctx, "192.168.1.1")
	assert.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "192.168.1.1", found.IPAddress)
}

func TestBlockedIPRepository_FindByIP_NotFound(t *testing.T) {
	db := setupBlockedIPDB(t)
	repo := repository.NewGormBlockedIPRepository(db)
	ctx := context.Background()

	found, err := repo.FindByIP(ctx, "192.168.1.1")
	assert.NoError(t, err)
	assert.Nil(t, found)
}

func TestBlockedIPRepository_FindActive(t *testing.T) {
	db := setupBlockedIPDB(t)
	repo := repository.NewGormBlockedIPRepository(db)
	ctx := context.Background()

	// Permanent block
	createTestBlockedIP(db, "192.168.1.1", "Permanent", true, nil)

	// Active temporary block
	futureTime := time.Now().Add(24 * time.Hour)
	createTestBlockedIP(db, "192.168.1.2", "Active temp", false, &futureTime)

	// Expired block
	pastTime := time.Now().Add(-24 * time.Hour)
	createTestBlockedIP(db, "192.168.1.3", "Expired", false, &pastTime)

	active, err := repo.FindActive(ctx)
	assert.NoError(t, err)
	assert.Len(t, active, 2) // Only permanent and active temp
}

func TestBlockedIPRepository_Create(t *testing.T) {
	db := setupBlockedIPDB(t)
	repo := repository.NewGormBlockedIPRepository(db)
	ctx := context.Background()

	blockedIP := &models.BlockedIP{
		IPAddress:   "192.168.1.1",
		Description: "Test block",
		Permanent:   true,
	}

	err := repo.Create(ctx, blockedIP)
	assert.NoError(t, err)
	assert.NotZero(t, blockedIP.ID)
}

func TestBlockedIPRepository_Update(t *testing.T) {
	db := setupBlockedIPDB(t)
	repo := repository.NewGormBlockedIPRepository(db)
	ctx := context.Background()

	blocked := createTestBlockedIP(db, "192.168.1.1", "Original", true, nil)

	blocked.Description = "Updated"
	blocked.Permanent = false

	err := repo.Update(ctx, &blocked)
	assert.NoError(t, err)

	updated, err := repo.FindByIP(ctx, "192.168.1.1")
	assert.NoError(t, err)
	assert.Equal(t, "Updated", updated.Description)
	assert.False(t, updated.Permanent)
}

func TestBlockedIPRepository_Delete(t *testing.T) {
	db := setupBlockedIPDB(t)
	repo := repository.NewGormBlockedIPRepository(db)
	ctx := context.Background()

	createTestBlockedIP(db, "192.168.1.1", "Test", true, nil)

	err := repo.Delete(ctx, "192.168.1.1")
	assert.NoError(t, err)

	found, err := repo.FindByIP(ctx, "192.168.1.1")
	assert.NoError(t, err)
	assert.Nil(t, found)
}

func TestBlockedIPRepository_IsBlocked(t *testing.T) {
	db := setupBlockedIPDB(t)
	repo := repository.NewGormBlockedIPRepository(db)
	ctx := context.Background()

	// Permanent block
	createTestBlockedIP(db, "192.168.1.1", "Permanent", true, nil)

	// Active temporary
	futureTime := time.Now().Add(24 * time.Hour)
	createTestBlockedIP(db, "192.168.1.2", "Active", false, &futureTime)

	// Expired
	pastTime := time.Now().Add(-24 * time.Hour)
	createTestBlockedIP(db, "192.168.1.3", "Expired", false, &pastTime)

	// Check permanent
	blocked, err := repo.IsBlocked(ctx, "192.168.1.1")
	assert.NoError(t, err)
	assert.True(t, blocked)

	// Check active temporary
	blocked, err = repo.IsBlocked(ctx, "192.168.1.2")
	assert.NoError(t, err)
	assert.True(t, blocked)

	// Check expired
	blocked, err = repo.IsBlocked(ctx, "192.168.1.3")
	assert.NoError(t, err)
	assert.False(t, blocked)

	// Check non-existent
	blocked, err = repo.IsBlocked(ctx, "192.168.1.99")
	assert.NoError(t, err)
	assert.False(t, blocked)
}

func TestBlockedIPRepository_Count(t *testing.T) {
	db := setupBlockedIPDB(t)
	repo := repository.NewGormBlockedIPRepository(db)
	ctx := context.Background()

	createTestBlockedIP(db, "192.168.1.1", "Test 1", true, nil)
	futureTime := time.Now().Add(24 * time.Hour)
	createTestBlockedIP(db, "192.168.1.2", "Test 2", false, &futureTime)

	count, err := repo.Count(ctx)
	assert.NoError(t, err)
	assert.Equal(t, int64(2), count)
}

func TestBlockedIPRepository_FindByIPAndDescription(t *testing.T) {
	db := setupBlockedIPDB(t)
	repo := repository.NewGormBlockedIPRepository(db)
	ctx := context.Background()

	createTestBlockedIP(db, "192.168.1.1", "SQL Injection", true, nil)
	createTestBlockedIP(db, "192.168.1.1", "XSS Attack", true, nil)

	found, err := repo.FindByIPAndDescription(ctx, "192.168.1.1", "SQL Injection")
	assert.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "192.168.1.1", found.IPAddress)
	assert.Equal(t, "SQL Injection", found.Description)
}

func TestBlockedIPRepository_FindByIPAndDescription_NotFound(t *testing.T) {
	db := setupBlockedIPDB(t)
	repo := repository.NewGormBlockedIPRepository(db)
	ctx := context.Background()

	found, err := repo.FindByIPAndDescription(ctx, "192.168.1.1", "Not exists")
	assert.NoError(t, err)
	assert.Nil(t, found)
}

func TestBlockedIPRepository_FindPaginated(t *testing.T) {
	db := setupBlockedIPDB(t)
	repo := repository.NewGormBlockedIPRepository(db)
	ctx := context.Background()

	for i := 0; i < 15; i++ {
		createTestBlockedIP(db, "192.168.1."+string(rune('0'+i)), "Test", true, nil)
	}

	// First page
	blocked, total, err := repo.FindPaginated(ctx, 0, 10)
	assert.NoError(t, err)
	assert.Len(t, blocked, 10)
	assert.Equal(t, int64(15), total)

	// Second page
	blocked, total, err = repo.FindPaginated(ctx, 10, 10)
	assert.NoError(t, err)
	assert.Len(t, blocked, 5)
	assert.Equal(t, int64(15), total)
}
