package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config contains all application configuration loaded from environment variables.
//
// Fields:
//   - Server (ServerConfig): HTTP server configuration
//   - Database (DatabaseConfig): Database connection configuration
//   - Auth (AuthConfig): Authentication and JWT configuration
//   - Logger (LoggerConfig): Logging configuration
//   - CORS (CORSConfig): CORS policy configuration
//   - RateLimit (RateLimitConfig): Rate limiting configuration
//
// Example Usage:
//   cfg := config.LoadFromEnv()
//   server := NewServer(cfg)
//
// Thread Safety: Read-only after initialization, safe for concurrent use.
//
// See Also: LoadFromEnv()
type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	Auth     AuthConfig
	Logger   LoggerConfig
	CORS     CORSConfig
	RateLimit RateLimitConfig
}

// ServerConfig contains HTTP server configuration.
//
// Thread Safety: Read-only after initialization, safe for concurrent use.
type ServerConfig struct {
	Port            int
	Host            string
	ShutdownTimeout time.Duration
}

// DatabaseConfig contains database connection configuration.
//
// Thread Safety: Read-only after initialization, safe for concurrent use.
type DatabaseConfig struct {
	Path             string
	MaxOpenConns     int
	MaxIdleConns     int
	ConnMaxLifetime  time.Duration
	LogQueries       bool
}

// AuthConfig contains authentication and JWT configuration.
//
// Thread Safety: Read-only after initialization, safe for concurrent use.
type AuthConfig struct {
	JWTSecret       string
	TokenExpiration time.Duration
	OTPWindow       time.Duration
}

// LoggerConfig contains logger configuration.
//
// Thread Safety: Read-only after initialization, safe for concurrent use.
type LoggerConfig struct {
	Level      string
	OutputPath string
}

// CORSConfig contains CORS policy configuration.
//
// Thread Safety: Read-only after initialization, safe for concurrent use.
type CORSConfig struct {
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	ExposedHeaders   []string
	MaxAge           int
	AllowCredentials bool
}

// RateLimitConfig contains rate limiting configuration.
//
// Thread Safety: Read-only after initialization, safe for concurrent use.
type RateLimitConfig struct {
	Enabled     bool
	RPS         int           // Requests per second
	BurstSize   int
	WindowTime  time.Duration
}

// LoadFromEnv carica la configurazione dalle variabili d'ambiente
func LoadFromEnv() *Config {
	return &Config{
		Server: ServerConfig{
			Port:            getEnvAsInt("PORT", 8081),
			Host:            getEnvAsString("SERVER_HOST", "0.0.0.0"),
			ShutdownTimeout: getEnvAsDuration("SERVER_SHUTDOWN_TIMEOUT", 30*time.Second),
		},
		Database: DatabaseConfig{
			Path:            getEnvAsString("DB_PATH", "./waf.db"),
			MaxOpenConns:    getEnvAsInt("DB_MAX_OPEN_CONNS", 25),
			MaxIdleConns:    getEnvAsInt("DB_MAX_IDLE_CONNS", 5),
			ConnMaxLifetime: getEnvAsDuration("DB_CONN_MAX_LIFETIME", 5*time.Minute),
			LogQueries:      getEnvAsBool("DB_LOG_QUERIES", false),
		},
		Auth: AuthConfig{
			JWTSecret:       getEnvAsString("JWT_SECRET", "your-secret-key"),
			TokenExpiration: getEnvAsDuration("TOKEN_EXPIRATION", 24*time.Hour),
			OTPWindow:       getEnvAsDuration("OTP_WINDOW", 30*time.Second),
		},
		Logger: LoggerConfig{
			Level:      getEnvAsString("LOG_LEVEL", "info"),
			OutputPath: getEnvAsString("LOG_OUTPUT", "stdout"),
		},
		CORS: CORSConfig{
			AllowedOrigins:   getEnvAsStringSlice("CORS_ALLOWED_ORIGINS", []string{"http://localhost:3000"}),
			AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"},
			AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
			ExposedHeaders:   []string{"Link"},
			MaxAge:           300,
			AllowCredentials: true,
		},
		RateLimit: RateLimitConfig{
			Enabled:    getEnvAsBool("RATE_LIMIT_ENABLED", true),
			RPS:        getEnvAsInt("RATE_LIMIT_RPS", 100),
			BurstSize:  getEnvAsInt("RATE_LIMIT_BURST", 150),
			WindowTime: getEnvAsDuration("RATE_LIMIT_WINDOW", 1*time.Second),
		},
	}
}

// Helper functions per leggere variabili d'ambiente

func getEnvAsString(name, defaultValue string) string {
	val := os.Getenv(name)
	if val == "" {
		return defaultValue
	}
	return val
}

func getEnvAsInt(name string, defaultValue int) int {
	val := os.Getenv(name)
	if val == "" {
		return defaultValue
	}
	intVal, err := strconv.Atoi(val)
	if err != nil {
		return defaultValue
	}
	return intVal
}

func getEnvAsBool(name string, defaultValue bool) bool {
	val := os.Getenv(name)
	if val == "" {
		return defaultValue
	}
	boolVal, err := strconv.ParseBool(val)
	if err != nil {
		return defaultValue
	}
	return boolVal
}

func getEnvAsDuration(name string, defaultValue time.Duration) time.Duration {
	val := os.Getenv(name)
	if val == "" {
		return defaultValue
	}
	duration, err := time.ParseDuration(val)
	if err != nil {
		return defaultValue
	}
	return duration
}

func getEnvAsStringSlice(name string, defaultValue []string) []string {
	val := os.Getenv(name)
	if val == "" {
		return defaultValue
	}
	// Parse comma-separated values
	parts := strings.Split(val, ",")
	var result []string
	for _, part := range parts {
		// Trim whitespace from each part
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	if len(result) == 0 {
		return defaultValue
	}
	return result
}
