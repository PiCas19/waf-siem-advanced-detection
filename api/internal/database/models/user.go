package models

import (
	"time"
	"gorm.io/gorm"
)

// User represents a dashboard user
type User struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Email        string `gorm:"uniqueIndex;not null" json:"email"`
	PasswordHash string `gorm:"not null" json:"-"`
	Name         string `json:"name"`
	Role         string `gorm:"default:'user'" json:"role"` // user, admin
	Active       bool   `gorm:"default:true" json:"active"`

	// 2FA (OTP) fields
	TwoFAEnabled bool   `gorm:"default:false" json:"two_fa_enabled"`
	OTPSecret    string `gorm:"default:''" json:"-"` // TOTP secret key (keep private)
	BackupCodes  string `gorm:"type:text" json:"-"` // JSON-encoded backup codes

	// Password reset / invite token (admin-created users)
	PasswordResetToken  string    `gorm:"index;size:128" json:"-"`
	PasswordResetExpiry time.Time `json:"-"`
}