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

func setupUserDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&models.User{})
	require.NoError(t, err)

	return db
}

func createTestUser(db *gorm.DB, email, name, role string, active bool) models.User {
	user := models.User{
		Email:        email,
		Name:         name,
		Role:         role,
		PasswordHash: "hashed_password",
		Active:       active,
	}
	db.Create(&user)
	return user
}

func TestNewGormUserRepository(t *testing.T) {
	db := setupUserDB(t)
	repo := repository.NewGormUserRepository(db)
	assert.NotNil(t, repo)
}

func TestUserRepository_FindAll(t *testing.T) {
	db := setupUserDB(t)
	repo := repository.NewGormUserRepository(db)
	ctx := context.Background()

	createTestUser(db, "user1@example.com", "User 1", "user", true)
	createTestUser(db, "user2@example.com", "User 2", "admin", true)
	createTestUser(db, "user3@example.com", "User 3", "user", false)

	users, err := repo.FindAll(ctx)
	assert.NoError(t, err)
	assert.Len(t, users, 3)
}

func TestUserRepository_FindByID(t *testing.T) {
	db := setupUserDB(t)
	repo := repository.NewGormUserRepository(db)
	ctx := context.Background()

	created := createTestUser(db, "test@example.com", "Test User", "user", true)

	found, err := repo.FindByID(ctx, created.ID)
	assert.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, created.ID, found.ID)
	assert.Equal(t, "test@example.com", found.Email)
}

func TestUserRepository_FindByID_NotFound(t *testing.T) {
	db := setupUserDB(t)
	repo := repository.NewGormUserRepository(db)
	ctx := context.Background()

	found, err := repo.FindByID(ctx, 9999)
	assert.NoError(t, err)
	assert.Nil(t, found)
}

func TestUserRepository_FindByEmail(t *testing.T) {
	db := setupUserDB(t)
	repo := repository.NewGormUserRepository(db)
	ctx := context.Background()

	createTestUser(db, "test@example.com", "Test User", "user", true)

	found, err := repo.FindByEmail(ctx, "test@example.com")
	assert.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, "test@example.com", found.Email)
}

func TestUserRepository_FindByEmail_NotFound(t *testing.T) {
	db := setupUserDB(t)
	repo := repository.NewGormUserRepository(db)
	ctx := context.Background()

	found, err := repo.FindByEmail(ctx, "nonexistent@example.com")
	assert.NoError(t, err)
	assert.Nil(t, found)
}

func TestUserRepository_Create(t *testing.T) {
	db := setupUserDB(t)
	repo := repository.NewGormUserRepository(db)
	ctx := context.Background()

	user := &models.User{
		Email:        "new@example.com",
		Name:         "New User",
		Role:         "user",
		PasswordHash: "hashed",
		Active:       true,
	}

	err := repo.Create(ctx, user)
	assert.NoError(t, err)
	assert.NotZero(t, user.ID)
}

func TestUserRepository_Update(t *testing.T) {
	db := setupUserDB(t)
	repo := repository.NewGormUserRepository(db)
	ctx := context.Background()

	user := createTestUser(db, "test@example.com", "Original Name", "user", true)

	user.Name = "Updated Name"
	user.Active = false

	err := repo.Update(ctx, &user)
	assert.NoError(t, err)

	// Verify update
	updated, err := repo.FindByID(ctx, user.ID)
	assert.NoError(t, err)
	assert.Equal(t, "Updated Name", updated.Name)
	assert.False(t, updated.Active)
}

func TestUserRepository_Delete(t *testing.T) {
	db := setupUserDB(t)
	repo := repository.NewGormUserRepository(db)
	ctx := context.Background()

	user := createTestUser(db, "test@example.com", "Test User", "user", true)

	err := repo.Delete(ctx, user.ID)
	assert.NoError(t, err)

	// Verify deletion (Unscoped delete, so record is gone)
	found, err := repo.FindByID(ctx, user.ID)
	assert.NoError(t, err)
	assert.Nil(t, found)
}

func TestUserRepository_Count(t *testing.T) {
	db := setupUserDB(t)
	repo := repository.NewGormUserRepository(db)
	ctx := context.Background()

	createTestUser(db, "user1@example.com", "User 1", "user", true)
	createTestUser(db, "user2@example.com", "User 2", "admin", true)
	createTestUser(db, "user3@example.com", "User 3", "user", false)

	count, err := repo.Count(ctx)
	assert.NoError(t, err)
	assert.Equal(t, int64(3), count)
}

func TestUserRepository_UpdateRole(t *testing.T) {
	db := setupUserDB(t)
	repo := repository.NewGormUserRepository(db)
	ctx := context.Background()

	user := createTestUser(db, "test@example.com", "Test User", "user", true)

	err := repo.UpdateRole(ctx, user.ID, "admin")
	assert.NoError(t, err)

	// Verify role update
	updated, err := repo.FindByID(ctx, user.ID)
	assert.NoError(t, err)
	assert.Equal(t, "admin", updated.Role)
}

func TestUserRepository_FindByRole(t *testing.T) {
	db := setupUserDB(t)
	repo := repository.NewGormUserRepository(db)
	ctx := context.Background()

	createTestUser(db, "user1@example.com", "User 1", "user", true)
	createTestUser(db, "admin1@example.com", "Admin 1", "admin", true)
	createTestUser(db, "admin2@example.com", "Admin 2", "admin", true)
	createTestUser(db, "user2@example.com", "User 2", "user", true)

	admins, err := repo.FindByRole(ctx, "admin")
	assert.NoError(t, err)
	assert.Len(t, admins, 2)
	
	for _, admin := range admins {
		assert.Equal(t, "admin", admin.Role)
	}
}

func TestUserRepository_CountByRole(t *testing.T) {
	db := setupUserDB(t)
	repo := repository.NewGormUserRepository(db)
	ctx := context.Background()

	createTestUser(db, "user1@example.com", "User 1", "user", true)
	createTestUser(db, "admin1@example.com", "Admin 1", "admin", true)
	createTestUser(db, "admin2@example.com", "Admin 2", "admin", true)

	adminCount, err := repo.CountByRole(ctx, "admin")
	assert.NoError(t, err)
	assert.Equal(t, int64(2), adminCount)

	userCount, err := repo.CountByRole(ctx, "user")
	assert.NoError(t, err)
	assert.Equal(t, int64(1), userCount)
}

func TestUserRepository_ExistsByEmail(t *testing.T) {
	db := setupUserDB(t)
	repo := repository.NewGormUserRepository(db)
	ctx := context.Background()

	createTestUser(db, "existing@example.com", "Existing User", "user", true)

	// Existing email
	exists, err := repo.ExistsByEmail(ctx, "existing@example.com")
	assert.NoError(t, err)
	assert.True(t, exists)

	// Non-existing email
	exists, err = repo.ExistsByEmail(ctx, "nonexistent@example.com")
	assert.NoError(t, err)
	assert.False(t, exists)
}

func TestUserRepository_FindPaginated(t *testing.T) {
	db := setupUserDB(t)
	repo := repository.NewGormUserRepository(db)
	ctx := context.Background()

	// Create 15 users
	for i := 0; i < 15; i++ {
		createTestUser(db, "user"+string(rune('0'+i))+"@example.com", "User", "user", true)
	}

	// First page
	users, total, err := repo.FindPaginated(ctx, 0, 10)
	assert.NoError(t, err)
	assert.Len(t, users, 10)
	assert.Equal(t, int64(15), total)

	// Second page
	users, total, err = repo.FindPaginated(ctx, 10, 10)
	assert.NoError(t, err)
	assert.Len(t, users, 5)
	assert.Equal(t, int64(15), total)
}

func TestUserRepository_CreateDuplicate(t *testing.T) {
	db := setupUserDB(t)
	repo := repository.NewGormUserRepository(db)
	ctx := context.Background()

	user1 := &models.User{
		Email:        "duplicate@example.com",
		Name:         "User 1",
		Role:         "user",
		PasswordHash: "hashed",
		Active:       true,
	}

	err := repo.Create(ctx, user1)
	assert.NoError(t, err)

	// Try to create duplicate
	user2 := &models.User{
		Email:        "duplicate@example.com",
		Name:         "User 2",
		Role:         "user",
		PasswordHash: "hashed",
		Active:       true,
	}

	err = repo.Create(ctx, user2)
	assert.Error(t, err) // Should fail due to unique constraint
}

func TestUserRepository_UpdateNonExistent(t *testing.T) {
	db := setupUserDB(t)
	repo := repository.NewGormUserRepository(db)
	ctx := context.Background()

	user := &models.User{
		ID:           9999,
		Email:        "nonexistent@example.com",
		Name:         "Non Existent",
		Role:         "user",
		PasswordHash: "hashed",
		Active:       true,
	}

	// Update should create if not exists with GORM's Save
	err := repo.Update(ctx, user)
	assert.NoError(t, err)
}
