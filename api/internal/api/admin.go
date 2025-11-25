package api

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/helpers"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/service"
)

// NewGetUsersHandler godoc
// @Summary Get users list
// @Description Returns paginated list of system users (admin-only)
// @Tags Admin
// @Accept json
// @Produce json
// @Param limit query int false "Number of users per page (default 20, max 100)" default(20)
// @Param offset query int false "Pagination offset (default 0)" default(0)
// @Success 200 {object} map[string]interface{} "Users with pagination"
// @Failure 400 {object} map[string]interface{} "Invalid parameters"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /admin/users [get]
// @Security BearerAuth
func NewGetUsersHandler(userService *service.UserService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Parse pagination parameters
		limit, offset, _, _, err := helpers.ParsePaginationParams(c)
		if err != nil {
			BadRequestWithCode(c, ErrInvalidRequest, err.Error())
			return
		}

		ctx := c.Request.Context()

		// Fetch paginated users
		users, total, err := userService.GetUsersPaginated(ctx, offset, limit)
		if err != nil {
			InternalServerErrorWithCode(c, ErrServiceError, "Failed to fetch users")
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

		// Build paginated response
		response := helpers.BuildStandardPaginatedResponse(out, limit, offset, total)

		c.JSON(http.StatusOK, gin.H{
			"users":      response.Items,
			"pagination": response.Pagination,
		})
	}
}

// Deprecated compatibility stub
func GetUsers(c *gin.Context) { BadRequest(c, "use NewGetUsersHandler") }

// NewUpdateUserHandler godoc
// @Summary Update user information
// @Description Updates user name, role, and active status (admin-only)
// @Tags Admin
// @Accept json
// @Produce json
// @Param id path int true "User ID"
// @Param request body object{name=string,role=string,active=boolean} true "Update request"
// @Success 200 {object} map[string]interface{} "User updated successfully"
// @Failure 400 {object} map[string]interface{} "Invalid user ID"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Cannot edit own account"
// @Failure 404 {object} map[string]interface{} "User not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /admin/users/{id} [put]
// @Security BearerAuth
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

// NewDeleteUserHandler godoc
// @Summary Delete a user
// @Description Deletes a user account (admin-only, cannot delete own account)
// @Tags Admin
// @Accept json
// @Produce json
// @Param id path int true "User ID"
// @Success 200 {object} map[string]interface{} "User deleted successfully"
// @Failure 400 {object} map[string]interface{} "Invalid user ID"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Cannot delete own account"
// @Failure 404 {object} map[string]interface{} "User not found"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /admin/users/{id} [delete]
// @Security BearerAuth
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