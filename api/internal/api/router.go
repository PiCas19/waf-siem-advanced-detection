package api

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/auth"
	mailerpkg "github.com/PiCas19/waf-siem-advanced-detection/api/internal/mailer"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/repository"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/service"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/websocket"
)

func SetupRoutes(r *gin.Engine, db *gorm.DB) {
	// init mailer (reads env vars). If not configured, mailer will be nil.
	mailer := mailerpkg.NewMailerFromEnv()
	authHandler := auth.NewAuthHandler(db, mailer)

	// Initialize repositories
	logRepo := repository.NewGormLogRepository(db)
	ruleRepo := repository.NewGormRuleRepository(db)
	blockedIPRepo := repository.NewGormBlockedIPRepository(db)
	whitelistRepo := repository.NewGormWhitelistedIPRepository(db)
	auditLogRepo := repository.NewGormAuditLogRepository(db)
	falsePositiveRepo := repository.NewGormFalsePositiveRepository(db)
	userRepo := repository.NewGormUserRepository(db)

	// Initialize services
	logService := service.NewLogService(logRepo)
	ruleService := service.NewRuleService(ruleRepo)
	blocklistService := service.NewBlocklistService(blockedIPRepo, logRepo)
	whitelistService := service.NewWhitelistService(whitelistRepo)
	auditLogService := service.NewAuditLogService(auditLogRepo)
	falsePositiveService := service.NewFalsePositiveService(falsePositiveRepo)
	userService := service.NewUserService(userRepo)

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
		public.POST("/waf/event", NewWAFEventHandler(logService, auditLogService, ruleService, blocklistService))
		// WAF endpoint to fetch custom rules
		public.GET("/waf/custom-rules", NewGetCustomRulesHandler(ruleService))
		// WAF endpoint to fetch blocklist/whitelist
		public.GET("/waf/blocklist", NewGetBlocklistForWAF(blocklistService))
		public.GET("/waf/whitelist", NewGetWhitelistForWAF(whitelistService))
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
			rules.GET("", NewGetRulesHandler(ruleService))
			rules.POST("", NewCreateRuleHandler(ruleService, db))
			rules.PUT("/:id", NewUpdateRuleHandler(ruleService, db))
			rules.DELETE("/:id", NewDeleteRuleHandler(ruleService, db))
			rules.PATCH("/:id/toggle", NewToggleRuleHandler(ruleService))
		}

		// Logs endpoints - accessible to analyst and above
		protected.GET("/logs", NewGetLogsHandler(logService, auditLogService, blocklistService))
		protected.POST("/logs/manual-block", NewLogManualBlockHandler())
		protected.POST("/logs/manual-unblock", NewLogManualUnblockHandler())

		// Audit logs endpoints
		protected.GET("/audit-logs", NewGetAuditLogsHandler(auditLogService))
		protected.GET("/audit-logs/stats", NewGetAuditLogStatsHandler(auditLogService))

		// Blocklist endpoints
		protected.GET("/blocklist", GetBlocklist(blocklistService))
		protected.POST("/blocklist", auth.PermissionMiddleware("blocklist_add"), NewBlockIPHandler(blocklistService, logService, ruleService))
		protected.DELETE("/blocklist/:ip", auth.PermissionMiddleware("blocklist_remove"), NewUnblockIPHandler(blocklistService, logService, ruleService))

		// Whitelist endpoints
		protected.GET("/whitelist", NewGetWhitelistHandler(whitelistService))
		protected.POST("/whitelist", auth.PermissionMiddleware("whitelist_add"), NewAddToWhitelistHandler(whitelistService))
		protected.DELETE("/whitelist/:id", auth.PermissionMiddleware("whitelist_remove"), NewRemoveFromWhitelistHandler(whitelistService))

		// False Positives endpoints
		protected.GET("/false-positives", NewGetFalsePositivesHandler(falsePositiveService))
		protected.POST("/false-positives", auth.PermissionMiddleware("false_positives_report"), NewReportFalsePositiveHandler(falsePositiveService))
		protected.PATCH("/false-positives/:id", auth.PermissionMiddleware("false_positives_resolve"), NewUpdateFalsePositiveStatusHandler(falsePositiveService))
		protected.DELETE("/false-positives/:id", auth.PermissionMiddleware("false_positives_delete"), NewDeleteFalsePositiveHandler(falsePositiveService))

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
		admin.GET("/users", NewGetUsersHandler(userService))
		// Admin-only user creation (invite flow)
		admin.POST("/users", authHandler.AdminCreateUser)
		// Update user (admin-only)
		admin.PUT("/users/:id", NewUpdateUserHandler(userService))
		// Delete user (admin-only)
		admin.DELETE("/users/:id", NewDeleteUserHandler(userService))
	}
}