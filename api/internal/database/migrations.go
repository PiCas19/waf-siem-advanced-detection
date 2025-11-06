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
		// Use a temporary struct to define the column
		type tempUser struct {
			MustSetup2FA bool `gorm:"default:false"`
		}
		if err := db.Migrator().AddColumn(&tempUser{}, "must_setup_2fa"); err != nil {
			log.Printf("[ERROR] Failed to add must_setup_2fa column: %v\n", err)
			return err
		}
		log.Println("[MIGRATION] ✅ Successfully added must_setup_2fa column")
	}

	return nil
}
