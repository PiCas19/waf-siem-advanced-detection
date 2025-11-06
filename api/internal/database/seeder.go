package database

import (
	"log"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
)

// SeedDefaultUsers creates the default root admin user if it doesn't exist
func SeedDefaultUsers(db *gorm.DB) error {
	// Check if root user already exists
	var existingUser models.User
	result := db.Where("email = ?", "root@admin.local").First(&existingUser)

	if result.Error == nil {
		log.Println("[INFO] Root admin user already exists, skipping seeding")
		return nil
	}

	if result.Error != gorm.ErrRecordNotFound {
		return result.Error
	}

	// Create root admin user
	// Default password: RootAdmin123!
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("RootAdmin123!"), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	rootUser := models.User{
		Email:        "root@admin.local",
		Name:         "Root Admin",
		Role:         "admin",
		Active:       true,
		PasswordHash: string(passwordHash),
		TwoFAEnabled: false,
		MustSetup2FA: true,  // Force 2FA setup on first login
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := db.Create(&rootUser).Error; err != nil {
		return err
	}

	log.Println("[INFO] ✅ Root admin user created successfully!")
	log.Println("[INFO] Email: root@admin.local")
	log.Println("[INFO] Password: RootAdmin123!")
	log.Println("[INFO] ⚠️  Please change the password after first login!")

	return nil
}
