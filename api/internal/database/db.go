package database

import (
    "gorm.io/driver/sqlite"
    "gorm.io/gorm"
    "os"
    "path/filepath"
    "time"

    "github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
    "github.com/PiCas19/waf-siem-advanced-detection/api/internal/logger"
)

// Initialize crea il DB e fa le migrazioni
func Initialize(dbPath string) (*gorm.DB, error) {
	startTime := time.Now()
	logger.Log.WithFields(map[string]interface{}{
		"operation": "database_initialization",
		"db_path":   dbPath,
	}).Info("Starting database initialization")

	// Crea la directory se non esiste
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		logger.Log.WithFields(map[string]interface{}{
			"operation": "database_initialization",
			"db_path":   dbPath,
			"directory": dir,
		}).WithError(err).Error("Failed to create database directory")
		return nil, err
	}

	logger.Log.WithFields(map[string]interface{}{
		"operation": "database_connection",
		"db_path":   dbPath,
	}).Info("Opening database connection")

    db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		logger.Log.WithFields(map[string]interface{}{
			"operation": "database_connection",
			"db_path":   dbPath,
		}).WithError(err).Error("Failed to open database connection")
		return nil, err
	}

	logger.Log.WithFields(map[string]interface{}{
		"operation": "database_connection",
		"db_path":   dbPath,
	}).Info("Database connection established successfully")

    // Improve SQLite concurrency for multi-process access (WAL + reasonable timeouts)
    // Ignore errors silently to keep compatibility if driver changes
	logger.Log.WithFields(map[string]interface{}{
		"operation": "database_optimization",
	}).Info("Configuring SQLite optimizations (WAL mode, synchronous, timeout)")

    _ = db.Exec("PRAGMA journal_mode=WAL;").Error
    _ = db.Exec("PRAGMA synchronous=NORMAL;").Error
    _ = db.Exec("PRAGMA busy_timeout=5000;").Error

	// Migrazioni
	logger.Log.WithFields(map[string]interface{}{
		"operation": "database_migration",
		"models": []string{"User", "Rule", "Log", "BlockedIP", "AuditLog", "FalsePositive", "WhitelistedIP"},
	}).Info("Starting database auto-migration")

	err = db.AutoMigrate(
		&models.User{},
		&models.Rule{},
		&models.Log{},
		&models.BlockedIP{},
		&models.AuditLog{},
		&models.FalsePositive{},
		&models.WhitelistedIP{},
	)
	if err != nil {
		logger.Log.WithFields(map[string]interface{}{
			"operation": "database_migration",
		}).WithError(err).Error("Failed to run database auto-migration")
		return nil, err
	}

	logger.Log.WithFields(map[string]interface{}{
		"operation": "database_migration",
	}).Info("Database auto-migration completed successfully")

	// Run custom migrations (backward compatibility)
	logger.Log.WithFields(map[string]interface{}{
		"operation": "custom_migrations",
	}).Info("Starting custom migrations")

	if err := RunMigrations(db); err != nil {
		logger.Log.WithFields(map[string]interface{}{
			"operation": "custom_migrations",
		}).WithError(err).Error("Failed to run custom migrations")
		return nil, err
	}

	// Run versioned schema migrations
	logger.Log.WithFields(map[string]interface{}{
		"operation": "schema_migrations",
	}).Info("Starting schema migrations")

	if err := RunSchemaMigrations(db); err != nil {
		logger.Log.WithFields(map[string]interface{}{
			"operation": "schema_migrations",
		}).WithError(err).Error("Failed to run schema migrations")
		return nil, err
	}

	duration := time.Since(startTime).Milliseconds()
	logger.Log.WithFields(map[string]interface{}{
		"operation":   "database_initialization",
		"db_path":     dbPath,
		"duration_ms": duration,
	}).Info("Database initialization completed successfully")

	return db, nil
}