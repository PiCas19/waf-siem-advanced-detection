package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
)

// NewGetUsersHandler returns a handler that lists users (admin-only)
func NewGetUsersHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var users []models.User
		if err := db.Find(&users).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load users"})
			return
		}

		// Build sanitized response (hide password, secrets, tokens)
		out := make([]gin.H, 0, len(users))
		for _, u := range users {
			out = append(out, gin.H{
				"id":             u.ID,
				"email":          u.Email,
				"name":           u.Name,
				"role":           u.Role,
				"active":         u.Active,
				"two_fa_enabled": u.TwoFAEnabled,
				"created_at":     u.CreatedAt,
				"updated_at":     u.UpdatedAt,
			})
		}

		c.JSON(http.StatusOK, gin.H{"users": out})
	}
}

// Deprecated compatibility stub
func GetUsers(c *gin.Context) { c.JSON(400, gin.H{"error": "use NewGetUsersHandler"}) }