package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/logger"
)

// TokenBucket implements a token bucket algorithm for rate limiting.
//
// Fields:
//   - tokens (float64): Current number of available tokens
//   - maxTokens (float64): Maximum token capacity
//   - refillRate (float64): Tokens added per second
//   - lastRefill (time.Time): Last refill timestamp
//   - mu (sync.Mutex): Mutex for thread-safe operations
//
// Thread Safety: Thread-safe via internal mutex locking.
//
// See Also: NewTokenBucket(), Allow()
type TokenBucket struct {
	tokens    float64
	maxTokens float64
	refillRate float64 // tokens per second
	lastRefill time.Time
	mu         sync.Mutex
}

// NewTokenBucket crea un nuovo token bucket
func NewTokenBucket(rps float64, burstSize int) *TokenBucket {
	return &TokenBucket{
		tokens:     float64(burstSize),
		maxTokens: float64(burstSize),
		refillRate: rps,
		lastRefill: time.Now(),
	}
}

// Allow tenta di prendere un token
func (tb *TokenBucket) Allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	// Riempi il bucket con i token generati dal tempo passato
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	tb.tokens = min(tb.maxTokens, tb.tokens+elapsed*tb.refillRate)
	tb.lastRefill = now

	// Prova a prendere un token
	if tb.tokens >= 1 {
		tb.tokens--
		return true
	}
	return false
}

// RateLimiter manages per-IP rate limiting using token buckets.
//
// Fields:
//   - buckets (map[string]*TokenBucket): Per-IP token buckets
//   - mu (sync.RWMutex): Mutex for thread-safe bucket management
//   - rps (float64): Requests per second limit
//   - burst (int): Maximum burst size
//
// Thread Safety: Thread-safe via internal mutex locking.
//
// See Also: NewRateLimiter(), RateLimitMiddleware()
type RateLimiter struct {
	buckets map[string]*TokenBucket
	mu      sync.RWMutex
	rps     float64
	burst   int
}

// NewRateLimiter crea un nuovo rate limiter
func NewRateLimiter(rps float64, burst int) *RateLimiter {
	return &RateLimiter{
		buckets: make(map[string]*TokenBucket),
		rps:     rps,
		burst:   burst,
	}
}

// Allow controlla se la richiesta è permessa
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	bucket, exists := rl.buckets[key]
	if !exists {
		// Crea un nuovo bucket per questa chiave (IP)
		bucket = NewTokenBucket(rl.rps, rl.burst)
		rl.buckets[key] = bucket
	}
	rl.mu.Unlock()

	return bucket.Allow()
}

// RateLimitMiddleware crea un middleware di rate limiting
func RateLimitMiddleware(rateLimiter *RateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()

		if !rateLimiter.Allow(clientIP) {
			logger.Log.WithFields(map[string]interface{}{
				"client_ip": clientIP,
				"path":      c.Request.URL.Path,
				"method":    c.Request.Method,
			}).Warn("Rate limit exceeded")

			c.Header("Retry-After", "60")
			// Return standardized error response with code
			c.JSON(http.StatusTooManyRequests, gin.H{
				"code":    "RATE_LIMIT_EXCEEDED",
				"message": "Too many requests, please try again later",
				"retry_after": 60,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// RateLimitByEndpoint crea un rate limiter per endpoint specifico
func RateLimitByEndpoint(rps float64, burst int) gin.HandlerFunc {
	limiter := NewRateLimiter(rps, burst)
	return RateLimitMiddleware(limiter)
}

// SensitiveEndpointRateLimiter limita gli endpoint sensibili (login, admin, etc.)
// Usa rate limit più stretto: 5 req/sec con burst di 10
func SensitiveEndpointRateLimiter() gin.HandlerFunc {
	return RateLimitByEndpoint(5, 10)
}

// GeneralAPIRateLimiter limita le API generiche
// Usa rate limit moderato: 30 req/sec con burst di 50
func GeneralAPIRateLimiter() gin.HandlerFunc {
	return RateLimitByEndpoint(30, 50)
}

// StrictRateLimiter per endpoint molto sensibili (force-break login attempts, mass operations)
// Usa rate limit molto stretto: 1 req/sec con burst di 3
func StrictRateLimiter() gin.HandlerFunc {
	return RateLimitByEndpoint(1, 3)
}

// Helper function
func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
