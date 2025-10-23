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
}