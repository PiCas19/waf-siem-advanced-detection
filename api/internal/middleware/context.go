package middleware

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/logger"
)

// RequestIDMiddleware aggiunge un request ID a ogni richiesta per tracciamento
func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetString("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}

		// Aggiungi al context
		ctx := context.WithValue(c.Request.Context(), "request_id", requestID)
		c.Request = c.Request.WithContext(ctx)

		// Aggiungi come header di risposta
		c.Header("X-Request-ID", requestID)

		// Log con request ID
		logger.WithFields(map[string]interface{}{
			"request_id": requestID,
			"method":     c.Request.Method,
			"path":       c.Request.URL.Path,
			"ip":         c.ClientIP(),
		}).Info("Request started")

		c.Next()

		// Log completamento richiesta
		logger.WithFields(map[string]interface{}{
			"request_id":   requestID,
			"status":       c.Writer.Status(),
			"bytes":        c.Writer.Size(),
		}).Info("Request completed")
	}
}

// ContextPropagationMiddleware propaga il context correttamente
func ContextPropagationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Usa il context della richiesta HTTP (propaga timeout/cancellazione)
		ctx := c.Request.Context()
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}
