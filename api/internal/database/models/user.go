package models

import (
	"time"
	"gorm.io/gorm"
)

// User represents a dashboard user with authentication and authorization capabilities.
//
// Fields:
//   - ID (uint): Primary key identifier for the user
//   - CreatedAt (time.Time): Timestamp when the user was created
//   - UpdatedAt (time.Time): Timestamp of last update
//   - DeletedAt (gorm.DeletedAt): Soft delete timestamp (indexed)
//   - Email (string): User's email address (unique, indexed, required)
//   - PasswordHash (string): Bcrypt hash of the user's password (not exported in JSON)
//   - Name (string): Display name of the user
//   - Role (string): User's role - "user", "analyst", "operator", or "admin" (default: "user")
//   - Active (bool): Whether the user account is active (default: false)
//   - TwoFAEnabled (bool): Whether 2FA/TOTP is enabled for this user (default: false)
//   - MustSetup2FA (bool): Flag to force 2FA setup on next login (default: false)
//   - OTPSecret (string): TOTP secret key for 2FA (not exported in JSON)
//   - BackupCodes (string): JSON-encoded array of backup codes for 2FA recovery (not exported)
//   - PasswordResetToken (string): Token for password reset/invite flow (indexed, not exported)
//   - PasswordResetExpiry (time.Time): Expiry timestamp for the reset token (not exported)
//
// Example Usage:
//   user := &models.User{
//       Email: "admin@example.com",
//       Name: "Administrator",
//       Role: "admin",
//       Active: true,
//   }
//   hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
//   user.PasswordHash = string(hashedPassword)
//   db.Create(&user)
//
// Thread Safety: This struct itself is not thread-safe. Use appropriate database
// transaction handling when creating/modifying users concurrently.
//
// See Also: UserRepository, UserService, AuthHandler
type User struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Email        string `gorm:"uniqueIndex;not null" json:"email"`
	PasswordHash string `gorm:"not null" json:"-"`
	Name         string `json:"name"`
	Role         string `gorm:"default:'user'" json:"role"` // user, admin
	Active       bool   `gorm:"default:false" json:"active"`

	// 2FA (OTP) fields
	TwoFAEnabled   bool   `gorm:"default:false" json:"two_fa_enabled"`
	MustSetup2FA   bool   `gorm:"default:false" json:"must_setup_2fa"`    // Flag to force 2FA setup on next login
	OTPSecret      string `gorm:"default:''" json:"-"`                     // TOTP secret key (keep private)
	BackupCodes    string `gorm:"type:text" json:"-"`                      // JSON-encoded backup codes

	// Password reset / invite token (admin-created users)
	PasswordResetToken  string    `gorm:"index;size:128" json:"-"`
	PasswordResetExpiry time.Time `json:"-"`
}