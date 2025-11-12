package helpers

import (
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
)

// SetupTestDB creates an in-memory SQLite database for testing
func SetupTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to create test database: %v", err)
	}

	// Migrate all models
	err = db.AutoMigrate(
		&models.User{},
		&models.AuditLog{},
		&models.Log{},
		&models.BlockedIP{},
		&models.WhitelistedIP{},
		&models.Rule{},
		&models.FalsePositive{},
	)
	if err != nil {
		t.Fatalf("failed to migrate models: %v", err)
	}

	return db
}

// CleanupTestDB cleans up the test database
func CleanupTestDB(t *testing.T, db *gorm.DB) {
	sqlDB, err := db.DB()
	if err != nil {
		t.Logf("failed to get database connection: %v", err)
		return
	}
	sqlDB.Close()
}

// ClearTable truncates a table
func ClearTable(t *testing.T, db *gorm.DB, model interface{}) {
	if err := db.Migrator().DropTable(model); err != nil {
		t.Logf("failed to drop table: %v", err)
	}
}
