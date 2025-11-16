package api

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/auth"
	mailerpkg "github.com/PiCas19/waf-siem-advanced-detection/api/internal/mailer"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/websocket"
)

func SetupRoutes(r *gin.Engine, db *gorm.DB) {
	// init mailer (reads env vars). If not configured, mailer will be nil.
	mailer := mailerpkg.NewMailerFromEnv()
	authHandler := auth.NewAuthHandler(db, mailer)

	r.GET("/ws", websocket.WSHub)

	public := r.Group("/api")
	{
		public.POST("/auth/login", authHandler.Login)
		// self-registration removed: admin-only user creation
		public.POST("/auth/verify-otp", authHandler.VerifyOTPLogin)
		// endpoint for users to set password using an invite/reset token
		public.POST("/auth/set-password", authHandler.SetPasswordWithToken)
		// Forgot password endpoints (public - no auth required)
		public.POST("/auth/forgot-password", authHandler.ForgotPassword)
		public.POST("/auth/reset-password", authHandler.ResetPassword)
		public.POST("/waf/event", NewWAFEventHandler(db))
		// WAF endpoint to fetch custom rules
		public.GET("/waf/custom-rules", NewGetCustomRulesHandler(db))
		// WAF endpoint to fetch blocklist/whitelist
		public.GET("/waf/blocklist", NewGetBlocklistForWAF(db))
		public.GET("/waf/whitelist", NewGetWhitelistForWAF(db))
		// WAF challenge verification endpoint
		public.POST("/waf/challenge/verify", NewWAFChallengeVerifyHandler(db))
	}

	protected := r.Group("/api")
	protected.Use(auth.AuthMiddleware())
	{
		protected.GET("/stats", WAFStatsHandler)
		protected.GET("/geolocation", GetGeolocationHandler(db))

		rules := protected.Group("/rules")
		{
			rules.GET("", NewGetRulesHandler(db))
			rules.POST("", NewCreateRuleHandler(db))
			rules.PUT("/:id", NewUpdateRuleHandler(db))
			rules.DELETE("/:id", NewDeleteRuleHandler(db))
			rules.PATCH("/:id/toggle", NewToggleRuleHandler(db))
		}

		// Logs endpoints - accessible to analyst and above
		protected.GET("/logs", NewGetLogsHandler(db))

		// Audit logs endpoints
		protected.GET("/audit-logs", NewGetAuditLogsHandler(db))
		protected.GET("/audit-logs/stats", NewGetAuditLogStatsHandler(db))

		// Blocklist endpoints
		protected.GET("/blocklist", GetBlocklist(db))
		protected.POST("/blocklist", auth.PermissionMiddleware("manage_threats"), NewBlockIPHandler(db))
		protected.DELETE("/blocklist/:ip", auth.PermissionMiddleware("manage_threats"), NewUnblockIPHandler(db))

		// Whitelist endpoints
		protected.GET("/whitelist", NewGetWhitelistHandler(db))
		protected.POST("/whitelist", auth.PermissionMiddleware("manage_whitelist"), NewAddToWhitelistHandler(db))
		protected.DELETE("/whitelist/:id", auth.PermissionMiddleware("manage_whitelist"), NewRemoveFromWhitelistHandler(db))

		// False Positives endpoints
		protected.GET("/false-positives", NewGetFalsePositivesHandler(db))
		protected.POST("/false-positives", auth.PermissionMiddleware("report_false_positives"), NewReportFalsePositiveHandler(db))
		protected.PATCH("/false-positives/:id", auth.PermissionMiddleware("resolve_false_positives"), NewUpdateFalsePositiveStatusHandler(db))
		protected.DELETE("/false-positives/:id", auth.PermissionMiddleware("delete_false_positives"), NewDeleteFalsePositiveHandler(db))

		// 2FA endpoints
		protected.POST("/auth/2fa/setup", authHandler.InitiateTwoFASetup)
		protected.POST("/auth/2fa/confirm", authHandler.CompleteTwoFASetup)
		protected.POST("/auth/2fa/disable", authHandler.DisableTwoFA)

		// Change password
		protected.POST("/auth/change-password", authHandler.ChangePassword)
	}

	admin := r.Group("/api/admin")
	admin.Use(auth.AuthMiddleware(), auth.AdminMiddleware())
	{
		// List users (admin-only)
		admin.GET("/users", NewGetUsersHandler(db))
		// Admin-only user creation (invite flow)
		admin.POST("/users", authHandler.AdminCreateUser)
		// Update user (admin-only)
		admin.PUT("/users/:id", NewUpdateUserHandler(db))
		// Delete user (admin-only)
		admin.DELETE("/users/:id", NewDeleteUserHandler(db))
	}
}