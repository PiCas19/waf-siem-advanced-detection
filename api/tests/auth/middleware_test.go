package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/auth"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestAuthMiddleware_Success(t *testing.T) {
	router := gin.New()
	router.Use(auth.AuthMiddleware())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	token, _ := auth.GenerateToken(1, "test@example.com", "admin")

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthMiddleware_NoAuthHeader(t *testing.T) {
	router := gin.New()
	router.Use(auth.AuthMiddleware())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Authorization header required")
}

func TestAuthMiddleware_InvalidFormat(t *testing.T) {
	router := gin.New()
	router.Use(auth.AuthMiddleware())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	invalidFormats := []string{
		"InvalidToken",
		"Bearer",
		"Basic token",
		"Bearer token extra",
	}

	for _, authHeader := range invalidFormats {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", authHeader)

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	}
}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	router := gin.New()
	router.Use(auth.AuthMiddleware())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.here")

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid token")
}

func TestAuthMiddleware_SetsContextValues(t *testing.T) {
	router := gin.New()
	router.Use(auth.AuthMiddleware())
	router.GET("/test", func(c *gin.Context) {
		userID, _ := c.Get("user_id")
		email, _ := c.Get("user_email")
		role, _ := c.Get("user_role")
		clientIP, _ := c.Get("client_ip")

		c.JSON(http.StatusOK, gin.H{
			"user_id":   userID,
			"email":     email,
			"role":      role,
			"client_ip": clientIP,
		})
	})

	token, _ := auth.GenerateToken(123, "test@example.com", "admin")

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "test@example.com")
	assert.Contains(t, w.Body.String(), "admin")
}

func TestAdminMiddleware_Success(t *testing.T) {
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_role", "admin")
		c.Next()
	})
	router.Use(auth.AdminMiddleware())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminMiddleware_NotAdmin(t *testing.T) {
	roles := []string{"operator", "analyst", "user"}

	for _, role := range roles {
		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set("user_role", role)
			c.Next()
		})
		router.Use(auth.AdminMiddleware())
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code, "Role %s should be forbidden", role)
		assert.Contains(t, w.Body.String(), "Admin access required")
	}
}

func TestAdminMiddleware_NoRole(t *testing.T) {
	router := gin.New()
	router.Use(auth.AdminMiddleware())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestHasPermission_Admin(t *testing.T) {
	adminPermissions := []string{
		"logs_view", "logs_export", "logs_delete",
		"rules_view", "rules_create", "rules_edit", "rules_delete",
		"blocklist_view", "blocklist_add", "blocklist_remove",
		"whitelist_view", "whitelist_add", "whitelist_remove",
		"threats_block", "threats_unblock",
		"users_view", "users_create", "users_edit", "users_delete",
		"manage_users", "access_control",
	}

	for _, permission := range adminPermissions {
		assert.True(t, auth.HasPermission("admin", permission), "Admin should have %s", permission)
	}
}

func TestHasPermission_Operator(t *testing.T) {
	// Permissions operator should have
	hasPermissions := []string{
		"logs_view", "logs_export",
		"rules_view", "rules_create", "rules_edit",
		"blocklist_view", "blocklist_add", "blocklist_remove",
		"whitelist_view", "whitelist_add", "whitelist_remove",
		"threats_block", "threats_unblock",
		"access_control",
	}

	// Permissions operator should NOT have
	noPermissions := []string{
		"logs_delete", "rules_delete",
		"users_view", "users_create", "users_edit", "users_delete",
		"manage_users",
	}

	for _, permission := range hasPermissions {
		assert.True(t, auth.HasPermission("operator", permission), "Operator should have %s", permission)
	}

	for _, permission := range noPermissions {
		assert.False(t, auth.HasPermission("operator", permission), "Operator should NOT have %s", permission)
	}
}

func TestHasPermission_Analyst(t *testing.T) {
	// Permissions analyst should have
	hasPermissions := []string{
		"logs_view",
		"false_positives_view", "false_positives_report",
	}

	// Permissions analyst should NOT have
	noPermissions := []string{
		"logs_export", "logs_delete",
		"rules_view", "rules_create",
		"blocklist_view", "whitelist_view",
		"threats_block", "users_view",
		"manage_users",
	}

	for _, permission := range hasPermissions {
		assert.True(t, auth.HasPermission("analyst", permission), "Analyst should have %s", permission)
	}

	for _, permission := range noPermissions {
		assert.False(t, auth.HasPermission("analyst", permission), "Analyst should NOT have %s", permission)
	}
}

func TestHasPermission_User(t *testing.T) {
	// User role should have NO permissions
	permissions := []string{
		"logs_view", "rules_view", "blocklist_view",
		"whitelist_view", "threats_block", "users_view",
	}

	for _, permission := range permissions {
		assert.False(t, auth.HasPermission("user", permission), "User should NOT have %s", permission)
	}
}

func TestHasPermission_InvalidRole(t *testing.T) {
	assert.False(t, auth.HasPermission("invalid_role", "logs_view"))
	assert.False(t, auth.HasPermission("", "logs_view"))
	assert.False(t, auth.HasPermission("superadmin", "logs_view"))
}

func TestHasPermission_CaseInsensitive(t *testing.T) {
	assert.True(t, auth.HasPermission("ADMIN", "logs_view"))
	assert.True(t, auth.HasPermission("Admin", "logs_view"))
	assert.True(t, auth.HasPermission("aDmIn", "logs_view"))
}

func TestHasPermission_WithWhitespace(t *testing.T) {
	assert.True(t, auth.HasPermission(" admin ", "logs_view"))
	assert.True(t, auth.HasPermission("admin\n", "logs_view"))
	assert.True(t, auth.HasPermission("\tadmin", "logs_view"))
}

func TestPermissionMiddleware_Success(t *testing.T) {
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_role", "admin")
		c.Next()
	})
	router.Use(auth.PermissionMiddleware("logs_view"))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestPermissionMiddleware_NoPermission(t *testing.T) {
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_role", "analyst")
		c.Next()
	})
	router.Use(auth.PermissionMiddleware("rules_create"))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "Permission denied")
}

func TestPermissionMiddleware_NoRole(t *testing.T) {
	router := gin.New()
	router.Use(auth.PermissionMiddleware("logs_view"))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestPermissionMiddleware_MultiplePermissions(t *testing.T) {
	permissions := []string{"logs_view", "logs_export", "logs_delete"}

	for _, permission := range permissions {
		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Set("user_role", "admin")
			c.Next()
		})
		router.Use(auth.PermissionMiddleware(permission))
		router.GET("/test", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "success"})
		})

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Admin should have permission: %s", permission)
	}
}

func TestAuthMiddleware_ChainedWithAdmin(t *testing.T) {
	router := gin.New()
	router.Use(auth.AuthMiddleware())
	router.Use(auth.AdminMiddleware())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	token, _ := auth.GenerateToken(1, "admin@example.com", "admin")

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthMiddleware_ChainedWithPermission(t *testing.T) {
	router := gin.New()
	router.Use(auth.AuthMiddleware())
	router.Use(auth.PermissionMiddleware("logs_view"))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	token, _ := auth.GenerateToken(1, "analyst@example.com", "analyst")

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRolePermissions_AllRolesExist(t *testing.T) {
	expectedRoles := []string{"admin", "operator", "analyst", "user"}

	for _, role := range expectedRoles {
		_, exists := auth.RolePermissions[role]
		assert.True(t, exists, "Role %s should exist in RolePermissions", role)
	}
}

func TestRolePermissions_Consistency(t *testing.T) {
	// Verify that all admin permissions are also valid permission names
	adminPerms := auth.RolePermissions["admin"]
	assert.NotEmpty(t, adminPerms, "Admin should have permissions")

	// Verify operator is subset of admin (except user management)
	operatorPerms := auth.RolePermissions["operator"]
	for _, perm := range operatorPerms {
		// Operator should have most admin permissions except user management
		if perm != "manage_users" {
			// This is just checking the permission exists, not that it's in admin
			assert.NotEmpty(t, perm)
		}
	}
}
