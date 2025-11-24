package database

import (
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/logger"
	"gorm.io/gorm"
)

// RunMigrations esegue tutte le migrazioni necessarie
func RunMigrations(db *gorm.DB) error {
	logger.Log.WithFields(map[string]interface{}{
		"operation": "run_migrations",
	}).Info("Checking for pending migrations")

	// Migration: Add MustSetup2FA column to users table
	if !db.Migrator().HasColumn("users", "must_setup_2fa") {
		logger.Log.WithFields(map[string]interface{}{
			"operation": "migration_must_setup_2fa",
			"table":     "users",
			"column":    "must_setup_2fa",
		}).Info("MIGRATION: Adding must_setup_2fa column to users table")
		// Use raw SQL to add the column with default value
		if err := db.Exec("ALTER TABLE users ADD COLUMN must_setup_2fa BOOLEAN DEFAULT 0").Error; err != nil {
			logger.Log.WithFields(map[string]interface{}{
				"operation": "migration_must_setup_2fa",
				"table":     "users",
				"column":    "must_setup_2fa",
			}).WithError(err).Error("Failed to add must_setup_2fa column")
			return err
		}
		logger.Log.WithFields(map[string]interface{}{
			"operation": "migration_must_setup_2fa",
			"table":     "users",
			"column":    "must_setup_2fa",
		}).Info("MIGRATION: Successfully added must_setup_2fa column")
	} else {
		logger.Log.WithFields(map[string]interface{}{
			"operation": "migration_must_setup_2fa",
			"table":     "users",
			"column":    "must_setup_2fa",
		}).Debug("Column must_setup_2fa already exists, skipping migration")
	}

	// Migration: Add ClientIPPublic column to logs table (for storing public IP from Tailscale/VPN clients)
	if !db.Migrator().HasColumn("logs", "client_ip_public") {
		logger.Log.WithFields(map[string]interface{}{
			"operation": "migration_client_ip_public",
			"table":     "logs",
			"column":    "client_ip_public",
		}).Info("MIGRATION: Adding client_ip_public column to logs table")
		// Use raw SQL to add the column with default empty string
		if err := db.Exec("ALTER TABLE logs ADD COLUMN client_ip_public TEXT DEFAULT ''").Error; err != nil {
			logger.Log.WithFields(map[string]interface{}{
				"operation": "migration_client_ip_public",
				"table":     "logs",
				"column":    "client_ip_public",
			}).WithError(err).Error("Failed to add client_ip_public column")
			return err
		}
		logger.Log.WithFields(map[string]interface{}{
			"operation": "migration_client_ip_public",
			"table":     "logs",
			"column":    "client_ip_public",
		}).Info("MIGRATION: Successfully added client_ip_public column")
	} else {
		logger.Log.WithFields(map[string]interface{}{
			"operation": "migration_client_ip_public",
			"table":     "logs",
			"column":    "client_ip_public",
		}).Debug("Column client_ip_public already exists, skipping migration")
	}

	logger.Log.WithFields(map[string]interface{}{
		"operation": "run_migrations",
	}).Info("All migrations completed successfully")

	return nil
}
