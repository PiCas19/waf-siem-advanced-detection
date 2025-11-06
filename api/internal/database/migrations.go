package database

import (
	"log"

	"gorm.io/gorm"
)

// RunMigrations esegue tutte le migrazioni necessarie
func RunMigrations(db *gorm.DB) error {
	// Migration: Add MustSetup2FA column to users table
	if !db.Migrator().HasColumn("users", "must_setup_2fa") {
		log.Println("[MIGRATION] Adding must_setup_2fa column to users table...")
		// Use raw SQL to add the column with default value
		if err := db.Exec("ALTER TABLE users ADD COLUMN must_setup_2fa BOOLEAN DEFAULT 0").Error; err != nil {
			log.Printf("[ERROR] Failed to add must_setup_2fa column: %v\n", err)
			return err
		}
		log.Println("[MIGRATION] ✅ Successfully added must_setup_2fa column")
	}

	return nil
}
