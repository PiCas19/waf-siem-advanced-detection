package api

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/service"
)

// NewGetUsersHandler returns a handler that lists users (admin-only)
func NewGetUsersHandler(userService *service.UserService) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()

		users, err := userService.GetAllUsers(ctx)
		if err != nil {
			InternalServerError(c, "failed to load users")
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
func GetUsers(c *gin.Context) { BadRequest(c, "use NewGetUsersHandler") }

// NewUpdateUserHandler returns a handler that updates a user (admin-only)
func NewUpdateUserHandler(userService *service.UserService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userIDStr := c.Param("id")
		userID, err := strconv.ParseUint(userIDStr, 10, 32)
		if err != nil {
			BadRequest(c, "invalid user id")
			return
		}

		// Get authenticated user ID from context
		authUserIDInterface, exists := c.Get("user_id")
		if !exists {
			Unauthorized(c, "unauthorized")
			return
		}
		authUserID, ok := authUserIDInterface.(uint)
		if !ok {
			Unauthorized(c, "invalid user id in token")
			return
		}

		// Prevent user from editing themselves
		if authUserID == uint(userID) {
			Forbidden(c, "cannot edit your own account")
			return
		}

		var req struct {
			Name   string `json:"name"`
			Role   string `json:"role"`
			Active *bool  `json:"active"` // Optional: only update if provided
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			BadRequest(c, err.Error())
			return
		}

		ctx := c.Request.Context()
		user, err := userService.GetUserByID(ctx, uint(userID))
		if err != nil {
			NotFound(c, "user not found")
			return
		}

		// Update fields
		if req.Name != "" {
			user.Name = req.Name
		}
		if req.Role != "" {
			user.Role = req.Role
		}
		// Only update Active if explicitly provided
		if req.Active != nil {
			user.Active = *req.Active
		}

		if err := userService.UpdateUser(ctx, user); err != nil {
			InternalServerError(c, "failed to update user")
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "User updated successfully",
			"user": gin.H{
				"id":             user.ID,
				"email":          user.Email,
				"name":           user.Name,
				"role":           user.Role,
				"active":         user.Active,
				"two_fa_enabled": user.TwoFAEnabled,
				"created_at":     user.CreatedAt,
				"updated_at":     user.UpdatedAt,
			},
		})
	}
}

// NewDeleteUserHandler returns a handler that deletes a user (admin-only)
func NewDeleteUserHandler(userService *service.UserService) gin.HandlerFunc {
	return func(c *gin.Context) {
		userIDStr := c.Param("id")
		userID, err := strconv.ParseUint(userIDStr, 10, 32)
		if err != nil {
			BadRequest(c, "invalid user id")
			return
		}

		// Get authenticated user ID from context
		authUserIDInterface, exists := c.Get("user_id")
		if !exists {
			Unauthorized(c, "unauthorized")
			return
		}
		authUserID, ok := authUserIDInterface.(uint)
		if !ok {
			Unauthorized(c, "invalid user id in token")
			return
		}

		// Prevent user from deleting themselves
		if authUserID == uint(userID) {
			Forbidden(c, "cannot delete your own account")
			return
		}

		ctx := c.Request.Context()
		user, err := userService.GetUserByID(ctx, uint(userID))
		if err != nil {
			NotFound(c, "user not found")
			return
		}

		if err := userService.DeleteUser(ctx, uint(userID)); err != nil {
			InternalServerError(c, "failed to delete user")
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("User %s deleted successfully", user.Email)})
	}
}