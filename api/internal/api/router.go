package api

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/auth"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/websocket"
)

func SetupRoutes(r *gin.Engine, db *gorm.DB) {
	authHandler := auth.NewAuthHandler(db)

	r.GET("/ws", websocket.WSHub)

	public := r.Group("/api")
	{
		public.POST("/auth/login", authHandler.Login)
		public.POST("/auth/register", authHandler.Register)
		public.POST("/waf/event", WAFEventHandler)
	}

	protected := r.Group("/api")
	protected.Use(auth.AuthMiddleware())
	{
		protected.GET("/stats", WAFStatsHandler)

		rules := protected.Group("/rules")
		{
			rules.GET("", GetRules)
			rules.POST("", CreateRule)
		}

		protected.GET("/logs", GetLogs)
		protected.GET("/blocklist", GetBlocklist)
	}

	admin := r.Group("/api/admin")
	admin.Use(auth.AuthMiddleware(), auth.AdminMiddleware())
	{
		admin.GET("/users", GetUsers)
	}
}