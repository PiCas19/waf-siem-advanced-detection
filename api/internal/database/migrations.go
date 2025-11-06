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
		if err := db.Migrator().AddColumn("users", "must_setup_2fa bool default false"); err != nil {
			log.Printf("[ERROR] Failed to add must_setup_2fa column: %v\n", err)
			return err
		}
		log.Println("[MIGRATION] ✅ Successfully added must_setup_2fa column")
	}

	return nil
}
