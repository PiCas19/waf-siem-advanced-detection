package models

import (
	"time"
	"gorm.io/gorm"
)

// Rule represents a WAF detection rule
type Rule struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
	
	Name        string `gorm:"not null" json:"name"`
	Pattern     string `gorm:"not null" json:"pattern"`
	Type        string `gorm:"not null" json:"type"` // xss, sqli, lfi, rfi, cmd
	Severity    string `gorm:"default:'medium'" json:"severity"` // low, medium, high, critical
	Action      string `gorm:"default:'log'" json:"action"` // log, block
	Enabled     bool   `gorm:"default:true" json:"enabled"`
	Description string `json:"description"`
	CreatedBy   uint   `json:"created_by"`
}