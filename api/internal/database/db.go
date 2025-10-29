package database

import (
    "gorm.io/driver/sqlite"
    "gorm.io/gorm"
    "os"
    "path/filepath"

    "github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
)

// Initialize crea il DB e fa le migrazioni
func Initialize(dbPath string) (*gorm.DB, error) {
	// Crea la directory se non esiste
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

    db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		return nil, err
	}

    // Improve SQLite concurrency for multi-process access (WAL + reasonable timeouts)
    // Ignore errors silently to keep compatibility if driver changes
    _ = db.Exec("PRAGMA journal_mode=WAL;").Error
    _ = db.Exec("PRAGMA synchronous=NORMAL;").Error
    _ = db.Exec("PRAGMA busy_timeout=5000;").Error
	
	// Migrazioni
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