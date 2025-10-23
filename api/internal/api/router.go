package api

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/auth"
)

// SetupRoutes configures all API routes
func SetupRoutes(r *gin.Engine, db *gorm.DB) {
	authHandler := auth.NewAuthHandler(db)
	
	// Public routes
	public := r.Group("/api")
	{
		public.POST("/auth/login", authHandler.Login)
		public.POST("/auth/register", authHandler.Register)
	}
	
	// Protected routes
	protected := r.Group("/api")
	protected.Use(auth.AuthMiddleware())
	{
		// Dashboard stats
		protected.GET("/stats", func(c *gin.Context) {
			c.JSON(200, gin.H{
				"threats_detected": 0,
				"requests_blocked": 0,
				"total_requests":   0,
			})
		})
		
		// Rules management
		rules := protected.Group("/rules")
		{
			rules.GET("", func(c *gin.Context) {
				c.JSON(200, gin.H{"rules": []interface{}{}})
			})
			rules.POST("", func(c *gin.Context) {
				c.JSON(201, gin.H{"message": "Rule created"})
			})
		}
		
		// Logs
		protected.GET("/logs", func(c *gin.Context) {
			c.JSON(200, gin.H{"logs": []interface{}{}})
		})
		
		// Blocklist
		protected.GET("/blocklist", func(c *gin.Context) {
			c.JSON(200, gin.H{"blocked_ips": []interface{}{}})
		})
	}
	
	// Admin-only routes
	admin := r.Group("/api/admin")
	admin.Use(auth.AuthMiddleware(), auth.AdminMiddleware())
	{
		admin.GET("/users", func(c *gin.Context) {
			c.JSON(200, gin.H{"users": []interface{}{}})
		})
	}
}