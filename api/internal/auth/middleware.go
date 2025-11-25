package auth

import (
	"net/http"
	"strings"
	
	"github.com/gin-gonic/gin"
)

// AuthMiddleware validates JWT tokens
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}
		
		// Extract token
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization format"})
			c.Abort()
			return
		}
		
		tokenString := parts[1]
		
		// Validate token
		claims, err := ValidateToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}
		
		// Set user info in context
		c.Set("user_id", claims.UserID)
		c.Set("user_email", claims.Email)
		c.Set("user_role", claims.Role)
		c.Set("client_ip", c.ClientIP())

		c.Next()
	}
}

// AdminMiddleware checks if user is admin
func AdminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		roleVal, exists := c.Get("user_role")
		roleStr, _ := roleVal.(string)
		if !exists || !HasPermission(roleStr, "manage_users") {
			c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// RolePermissions maps roles to a list of capabilities/permissions.
// Add or adjust permissions here to control what each role can do.
// IMPORTANT: Keep in sync with dashboard/src/types/rbac.ts ROLE_PERMISSIONS
var RolePermissions = map[string][]string{
	"admin":    {
		// Admin: Full access
		"logs_view", "logs_export", "logs_delete",
		"rules_view", "rules_create", "rules_edit", "rules_delete",
		"blocklist_view", "blocklist_add", "blocklist_remove",
		"whitelist_view", "whitelist_add", "whitelist_remove",
		"false_positives_view", "false_positives_report", "false_positives_resolve", "false_positives_delete",
		"threats_block", "threats_unblock",
		"users_view", "users_create", "users_edit", "users_delete", "users_change_role",
		"manage_users",  // Required by AdminMiddleware
		"access_control",
	},
	"operator": {
		// Operator: Can do everything except manage users
		"logs_view", "logs_export",  // Can view/export logs but not delete
		"rules_view", "rules_create", "rules_edit",  // Can create/edit but not delete
		"blocklist_view", "blocklist_add", "blocklist_remove",
		"whitelist_view", "whitelist_add", "whitelist_remove",
		"false_positives_view", "false_positives_report", "false_positives_resolve", "false_positives_delete",  // Can manage all FP
		"threats_block", "threats_unblock",
		"access_control",
		// NO: users_view, users_create, users_edit, users_delete, users_change_role
	},
	"analyst": {
		// Analyst: Read-only access to logs and dashboard, can report false positives
		"logs_view",  // Can view but not export/delete
		"false_positives_view", "false_positives_report",  // Can view and report false positives
		// NO: rules, blocklist, whitelist, threats, users
	},
	"user": {
		// User: Minimal access - only dashboard
		// NO PERMISSIONS
	},
}

// HasPermission returns true if the role has the requested permission.
func HasPermission(role, permission string) bool {
	if role == "" {
		return false
	}
	role = strings.ToLower(strings.TrimSpace(role))
	perms, ok := RolePermissions[role]
	if !ok {
		return false
	}
	for _, p := range perms {
		if p == permission {
			return true
		}
	}
	return false
}

// PermissionMiddleware verifies that the authenticated user has the given permission.
func PermissionMiddleware(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		roleVal, exists := c.Get("user_role")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{"error": "Permission denied"})
			c.Abort()
			return
		}
		roleStr, _ := roleVal.(string)
		if !HasPermission(roleStr, permission) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Permission denied"})
			c.Abort()
			return
		}
		c.Next()
	}
}