package database

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
)

// Initialize creates database connection and runs migrations
func Initialize(dbPath string) (*gorm.DB, error) {
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	
	// Run migrations
	err = db.AutoMigrate(
		&models.User{},
		&models.Rule{},
		&models.Log{},
		&models.BlockedIP{},
	)
	if err != nil {
		return nil, err
	}
	
	return db, nil
}