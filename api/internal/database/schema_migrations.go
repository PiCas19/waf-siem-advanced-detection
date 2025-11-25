package database

import (
	"fmt"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/logger"
	"gorm.io/gorm"
)

// SchemaMigration tracks which migrations have been run
type SchemaMigration struct {
	ID        uint      `gorm:"primaryKey"`
	Version   string    `gorm:"uniqueIndex;column:version"`
	Name      string    `gorm:"column:name"`
	AppliedAt time.Time `gorm:"column:applied_at;autoCreateTime"`
}

// TableName specifies the table name for SchemaMigration
func (SchemaMigration) TableName() string {
	return "schema_migrations"
}

// Migration represents a single database migration
type Migration struct {
	Version string
	Name    string
	Up      func(*gorm.DB) error
	Down    func(*gorm.DB) error
}

// Migrations list all available migrations in order
var Migrations = []Migration{
	{
		Version: "001",
		Name:    "add_must_setup_2fa_to_users",
		Up: func(db *gorm.DB) error {
			if !db.Migrator().HasColumn("users", "must_setup_2fa") {
				logger.Log.Info("Migrazione 001: Aggiungendo colonna must_setup_2fa alla tabella users")
				return db.Migrator().AddColumn(&struct{ MustSetup2FA bool }{}, "must_setup_2fa")
			}
			return nil
		},
		Down: func(db *gorm.DB) error {
			return db.Migrator().DropColumn("users", "must_setup_2fa")
		},
	},
	{
		Version: "002",
		Name:    "add_client_ip_public_to_logs",
		Up: func(db *gorm.DB) error {
			if !db.Migrator().HasColumn("logs", "client_ip_public") {
				logger.Log.Info("Migrazione 002: Aggiungendo colonna client_ip_public alla tabella logs")
				return db.Migrator().AddColumn(&struct{ ClientIPPublic string }{}, "client_ip_public")
			}
			return nil
		},
		Down: func(db *gorm.DB) error {
			return db.Migrator().DropColumn("logs", "client_ip_public")
		},
	},
	{
		Version: "003",
		Name:    "add_index_on_logs_created_at",
		Up: func(db *gorm.DB) error {
			if !db.Migrator().HasIndex("logs", "created_at") {
				logger.Log.Info("Migrazione 003: Creando indice su logs.created_at per performance")
				return db.Migrator().CreateIndex("logs", "created_at")
			}
			return nil
		},
		Down: func(db *gorm.DB) error {
			return db.Migrator().DropIndex("logs", "created_at")
		},
	},
	{
		Version: "004",
		Name:    "add_index_on_blocked_ips",
		Up: func(db *gorm.DB) error {
			if !db.Migrator().HasIndex("blocked_ips", "ip_address") {
				logger.Log.Info("Migrazione 004: Creando indice su blocked_ips.ip_address per performance")
				return db.Migrator().CreateIndex("blocked_ips", "ip_address")
			}
			return nil
		},
		Down: func(db *gorm.DB) error {
			return db.Migrator().DropIndex("blocked_ips", "ip_address")
		},
	},
	{
		Version: "005",
		Name:    "add_index_on_rules_enabled",
		Up: func(db *gorm.DB) error {
			if !db.Migrator().HasIndex("rules", "enabled") {
				logger.Log.Info("Migrazione 005: Creando indice su rules.enabled per performance")
				return db.Migrator().CreateIndex("rules", "enabled")
			}
			return nil
		},
		Down: func(db *gorm.DB) error {
			return db.Migrator().DropIndex("rules", "enabled")
		},
	},
}

// RunSchemaMigrations esegue tutte le migrazioni in ordine
func RunSchemaMigrations(db *gorm.DB) error {
	// Create schema_migrations table
	if err := db.AutoMigrate(&SchemaMigration{}); err != nil {
		logger.Log.WithError(err).Error("Failed to create schema_migrations table")
		return err
	}

	logger.Log.Info("Starting schema migrations...")

	for _, migration := range Migrations {
		var existingMigration SchemaMigration
		result := db.Where("version = ?", migration.Version).First(&existingMigration)

		if result.Error != nil && result.Error != gorm.ErrRecordNotFound {
			logger.Log.WithError(result.Error).Errorf("Error checking migration %s", migration.Version)
			return result.Error
		}

		// Migration already applied
		if result.Error == nil {
			logger.Log.Debugf("Migration %s (%s) already applied", migration.Version, migration.Name)
			continue
		}

		// Run the migration
		logger.Log.Infof("Running migration %s (%s)", migration.Version, migration.Name)
		if err := migration.Up(db); err != nil {
			logger.Log.WithError(err).Errorf("Migration %s failed", migration.Version)
			return err
		}

		// Record the migration
		if err := db.Create(&SchemaMigration{
			Version: migration.Version,
			Name:    migration.Name,
		}).Error; err != nil {
			logger.Log.WithError(err).Errorf("Failed to record migration %s", migration.Version)
			return err
		}

		logger.Log.Infof("Migration %s (%s) completed successfully", migration.Version, migration.Name)
	}

	logger.Log.Info("All schema migrations completed successfully")
	return nil
}

// GetAppliedMigrations returns all migrations that have been applied
func GetAppliedMigrations(db *gorm.DB) ([]SchemaMigration, error) {
	var migrations []SchemaMigration
	if err := db.Order("version ASC").Find(&migrations).Error; err != nil {
		return nil, err
	}
	return migrations, nil
}

// RollbackMigration rolls back a specific migration (careful!)
func RollbackMigration(db *gorm.DB, version string) error {
	// Find the migration
	var migration Migration
	for _, m := range Migrations {
		if m.Version == version {
			migration = m
			break
		}
	}

	if migration.Version == "" {
		return fmt.Errorf("migration %s not found", version)
	}

	// Run the Down function
	logger.Log.Warnf("Rolling back migration %s (%s)", migration.Version, migration.Name)
	if err := migration.Down(db); err != nil {
		logger.Log.WithError(err).Errorf("Rollback of migration %s failed", migration.Version)
		return err
	}

	// Remove from schema_migrations
	if err := db.Where("version = ?", version).Delete(&SchemaMigration{}).Error; err != nil {
		logger.Log.WithError(err).Errorf("Failed to remove migration %s from schema_migrations", migration.Version)
		return err
	}

	logger.Log.Infof("Migration %s rolled back successfully", migration.Version)
	return nil
}
