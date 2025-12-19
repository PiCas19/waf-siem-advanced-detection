package api

import (
	"testing"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/api"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// TestSetupRoutes tests the route setup function
func TestSetupRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create in-memory database
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Auto-migrate all models to create tables
	err = db.AutoMigrate(
		&models.User{},
		&models.Log{},
		&models.Rule{},
		&models.BlockedIP{},
		&models.WhitelistedIP{},
		&models.AuditLog{},
		&models.FalsePositive{},
	)
	require.NoError(t, err)

	// Create a new Gin engine
	r := gin.New()

	// Setup routes (this should execute without errors)
	api.SetupRoutes(r, db)

	// Get all registered routes
	routes := r.Routes()

	// Verify routes were registered
	assert.NotEmpty(t, routes, "Routes should be registered")

	// Verify some key routes exist
	routePaths := make(map[string]bool)
	for _, route := range routes {
		routePaths[route.Method+" "+route.Path] = true
	}

	// Check public routes
	assert.True(t, routePaths["POST /api/auth/login"], "Login route should exist")
	assert.True(t, routePaths["POST /api/auth/verify-otp"], "OTP verification route should exist")
	assert.True(t, routePaths["POST /api/auth/set-password"], "Set password route should exist")
	assert.True(t, routePaths["POST /api/auth/forgot-password"], "Forgot password route should exist")
	assert.True(t, routePaths["POST /api/auth/reset-password"], "Reset password route should exist")
	assert.True(t, routePaths["POST /api/waf/event"], "WAF event route should exist")
	assert.True(t, routePaths["GET /api/waf/custom-rules"], "Custom rules route should exist")
	assert.True(t, routePaths["GET /api/waf/blocklist"], "WAF blocklist route should exist")
	assert.True(t, routePaths["GET /api/waf/whitelist"], "WAF whitelist route should exist")
	assert.True(t, routePaths["POST /api/waf/challenge/verify"], "WAF challenge verify route should exist")

	// Check protected routes
	assert.True(t, routePaths["GET /api/stats"], "Stats route should exist")
	assert.True(t, routePaths["GET /api/geolocation"], "Geolocation route should exist")
	assert.True(t, routePaths["GET /api/logs"], "Logs route should exist")
	assert.True(t, routePaths["PUT /api/logs/threat-status"], "Update threat status route should exist")
	assert.True(t, routePaths["GET /api/audit-logs"], "Audit logs route should exist")
	assert.True(t, routePaths["GET /api/audit-logs/stats"], "Audit log stats route should exist")
	assert.True(t, routePaths["GET /api/blocklist"], "Blocklist route should exist")
	assert.True(t, routePaths["POST /api/blocklist"], "Block IP route should exist")
	assert.True(t, routePaths["DELETE /api/blocklist/:ip"], "Unblock IP route should exist")
	assert.True(t, routePaths["GET /api/whitelist"], "Whitelist route should exist")
	assert.True(t, routePaths["POST /api/whitelist"], "Add to whitelist route should exist")
	assert.True(t, routePaths["DELETE /api/whitelist/:id"], "Remove from whitelist route should exist")
	assert.True(t, routePaths["GET /api/false-positives"], "False positives route should exist")
	assert.True(t, routePaths["POST /api/false-positives"], "Report false positive route should exist")
	assert.True(t, routePaths["PATCH /api/false-positives/:id"], "Update false positive route should exist")
	assert.True(t, routePaths["DELETE /api/false-positives/:id"], "Delete false positive route should exist")

	// Check rules routes
	assert.True(t, routePaths["GET /api/rules"], "Get rules route should exist")
	assert.True(t, routePaths["POST /api/rules"], "Create rule route should exist")
	assert.True(t, routePaths["PUT /api/rules/:id"], "Update rule route should exist")
	assert.True(t, routePaths["DELETE /api/rules/:id"], "Delete rule route should exist")
	assert.True(t, routePaths["PATCH /api/rules/:id/toggle"], "Toggle rule route should exist")

	// Check 2FA routes
	assert.True(t, routePaths["POST /api/auth/2fa/setup"], "2FA setup route should exist")
	assert.True(t, routePaths["POST /api/auth/2fa/confirm"], "2FA confirm route should exist")
	assert.True(t, routePaths["POST /api/auth/2fa/disable"], "2FA disable route should exist")

	// Check change password route
	assert.True(t, routePaths["POST /api/auth/change-password"], "Change password route should exist")

	// Check export routes
	assert.True(t, routePaths["GET /api/export/logs"], "Export logs route should exist")
	assert.True(t, routePaths["GET /api/export/audit-logs"], "Export audit logs route should exist")
	assert.True(t, routePaths["GET /api/export/blocklist"], "Export blocklist route should exist")

	// Check admin routes
	assert.True(t, routePaths["GET /api/admin/users"], "Admin get users route should exist")
	assert.True(t, routePaths["POST /api/admin/users"], "Admin create user route should exist")
	assert.True(t, routePaths["PUT /api/admin/users/:id"], "Admin update user route should exist")
	assert.True(t, routePaths["DELETE /api/admin/users/:id"], "Admin delete user route should exist")

	// Check WebSocket route
	assert.True(t, routePaths["GET /ws"], "WebSocket route should exist")

	// Verify we have a reasonable number of routes
	assert.GreaterOrEqual(t, len(routes), 35, "Should have at least 35 routes registered")
}

// TestSetupRoutes_VerifyRouteCount verifies the exact count of routes
func TestSetupRoutes_VerifyRouteCount(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create in-memory database
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Auto-migrate all models
	err = db.AutoMigrate(
		&models.User{},
		&models.Log{},
		&models.Rule{},
		&models.BlockedIP{},
		&models.WhitelistedIP{},
		&models.AuditLog{},
		&models.FalsePositive{},
	)
	require.NoError(t, err)

	// Create a new Gin engine
	r := gin.New()

	// Setup routes
	api.SetupRoutes(r, db)

	// Get all registered routes
	routes := r.Routes()

	// Count routes by type
	publicRoutes := 0
	protectedRoutes := 0
	adminRoutes := 0
	wsRoutes := 0

	for _, route := range routes {
		if route.Path == "/ws" {
			wsRoutes++
		} else if len(route.Path) >= 10 && route.Path[:10] == "/api/admin" {
			adminRoutes++
		} else if len(route.Path) >= 4 && route.Path[:4] == "/api" {
			// Check if it's a public route (no auth middleware)
			isPublic := route.Path == "/api/auth/login" ||
				route.Path == "/api/auth/verify-otp" ||
				route.Path == "/api/auth/set-password" ||
				route.Path == "/api/auth/forgot-password" ||
				route.Path == "/api/auth/reset-password" ||
				route.Path == "/api/waf/event" ||
				route.Path == "/api/waf/custom-rules" ||
				route.Path == "/api/waf/blocklist" ||
				route.Path == "/api/waf/whitelist" ||
				route.Path == "/api/waf/challenge/verify"

			if isPublic {
				publicRoutes++
			} else {
				protectedRoutes++
			}
		}
	}

	// Verify counts
	assert.Equal(t, 1, wsRoutes, "Should have 1 WebSocket route")
	assert.Equal(t, 10, publicRoutes, "Should have 10 public routes")
	assert.Equal(t, 4, adminRoutes, "Should have 4 admin routes")
	assert.GreaterOrEqual(t, protectedRoutes, 20, "Should have at least 20 protected routes")
}
