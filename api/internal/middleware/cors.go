package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/config"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/logger"
)

// CORSMiddleware configures CORS headers based on configuration
// Supports origin whitelist, wildcard, and standard CORS methods/headers
func CORSMiddleware(cfg *config.CORSConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")

		// Check if origin is in whitelist
		allowed := false
		for _, allowedOrigin := range cfg.AllowedOrigins {
			if allowedOrigin == "*" || origin == allowedOrigin {
				allowed = true
				break
			}
		}

		// Set origin header only if allowed
		if allowed {
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
		}

		// Set standard CORS headers
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID")
		c.Writer.Header().Set("Access-Control-Expose-Headers", "X-Request-ID, Content-Length")
		c.Writer.Header().Set("Access-Control-Max-Age", "300")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")

		// Handle OPTIONS preflight requests
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		// Log CORS checks if not allowed
		if !allowed && origin != "" {
			logger.Log.WithFields(map[string]interface{}{
				"action": "cors_check",
				"origin": origin,
				"allowed": false,
			}).Warn("CORS request from unauthorized origin")
		}

		c.Next()
	}
}
