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

	// Migration: Add ClientIPPublic column to logs table (for storing public IP from Tailscale/VPN clients)
	if !db.Migrator().HasColumn("logs", "client_ip_public") {
		log.Println("[MIGRATION] Adding client_ip_public column to logs table...")
		// Use raw SQL to add the column with default empty string
		if err := db.Exec("ALTER TABLE logs ADD COLUMN client_ip_public TEXT DEFAULT ''").Error; err != nil {
			log.Printf("[ERROR] Failed to add client_ip_public column: %v\n", err)
			return err
		}
		log.Println("[MIGRATION] ✅ Successfully added client_ip_public column")
	}

	return nil
}
