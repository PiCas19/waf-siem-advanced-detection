package config

import (
	"os"
	"testing"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cleanEnv clears all test-related environment variables
func cleanEnv() {
	envVars := []string{
		"PORT", "SERVER_HOST", "SERVER_SHUTDOWN_TIMEOUT",
		"DB_PATH", "DB_MAX_OPEN_CONNS", "DB_MAX_IDLE_CONNS", "DB_CONN_MAX_LIFETIME", "DB_LOG_QUERIES",
		"JWT_SECRET", "TOKEN_EXPIRATION", "OTP_WINDOW",
		"LOG_LEVEL", "LOG_OUTPUT",
		"CORS_ALLOWED_ORIGINS",
		"RATE_LIMIT_ENABLED", "RATE_LIMIT_RPS", "RATE_LIMIT_BURST", "RATE_LIMIT_WINDOW",
	}
	for _, env := range envVars {
		os.Unsetenv(env)
	}
}

// TestLoadFromEnv_Defaults tests loading config with default values
func TestLoadFromEnv_Defaults(t *testing.T) {
	cleanEnv()
	
	cfg := config.LoadFromEnv()
	
	require.NotNil(t, cfg)
	
	// Server defaults
	assert.Equal(t, 8081, cfg.Server.Port)
	assert.Equal(t, "0.0.0.0", cfg.Server.Host)
	assert.Equal(t, 30*time.Second, cfg.Server.ShutdownTimeout)
	
	// Database defaults
	assert.Equal(t, "./waf.db", cfg.Database.Path)
	assert.Equal(t, 25, cfg.Database.MaxOpenConns)
	assert.Equal(t, 5, cfg.Database.MaxIdleConns)
	assert.Equal(t, 5*time.Minute, cfg.Database.ConnMaxLifetime)
	assert.False(t, cfg.Database.LogQueries)
	
	// Auth defaults
	assert.Equal(t, "your-secret-key", cfg.Auth.JWTSecret)
	assert.Equal(t, 24*time.Hour, cfg.Auth.TokenExpiration)
	assert.Equal(t, 30*time.Second, cfg.Auth.OTPWindow)
	
	// Logger defaults
	assert.Equal(t, "info", cfg.Logger.Level)
	assert.Equal(t, "stdout", cfg.Logger.OutputPath)
	
	// CORS defaults
	assert.Equal(t, []string{"http://localhost:3000"}, cfg.CORS.AllowedOrigins)
	assert.Equal(t, []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"}, cfg.CORS.AllowedMethods)
	assert.Equal(t, []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"}, cfg.CORS.AllowedHeaders)
	assert.Equal(t, []string{"Link"}, cfg.CORS.ExposedHeaders)
	assert.Equal(t, 300, cfg.CORS.MaxAge)
	assert.True(t, cfg.CORS.AllowCredentials)
	
	// RateLimit defaults
	assert.True(t, cfg.RateLimit.Enabled)
	assert.Equal(t, 100, cfg.RateLimit.RPS)
	assert.Equal(t, 150, cfg.RateLimit.BurstSize)
	assert.Equal(t, 1*time.Second, cfg.RateLimit.WindowTime)
}

// TestLoadFromEnv_CustomValues tests loading config with custom environment variables
func TestLoadFromEnv_CustomValues(t *testing.T) {
	cleanEnv()
	
	// Set custom values
	os.Setenv("PORT", "9090")
	os.Setenv("SERVER_HOST", "127.0.0.1")
	os.Setenv("SERVER_SHUTDOWN_TIMEOUT", "60s")
	os.Setenv("DB_PATH", "/custom/path/db.sqlite")
	os.Setenv("DB_MAX_OPEN_CONNS", "50")
	os.Setenv("DB_MAX_IDLE_CONNS", "10")
	os.Setenv("DB_CONN_MAX_LIFETIME", "10m")
	os.Setenv("DB_LOG_QUERIES", "true")
	os.Setenv("JWT_SECRET", "custom-secret")
	os.Setenv("TOKEN_EXPIRATION", "48h")
	os.Setenv("OTP_WINDOW", "60s")
	os.Setenv("LOG_LEVEL", "debug")
	os.Setenv("LOG_OUTPUT", "/var/log/app.log")
	os.Setenv("CORS_ALLOWED_ORIGINS", "http://example.com,https://app.example.com")
	os.Setenv("RATE_LIMIT_ENABLED", "false")
	os.Setenv("RATE_LIMIT_RPS", "200")
	os.Setenv("RATE_LIMIT_BURST", "300")
	os.Setenv("RATE_LIMIT_WINDOW", "2s")
	
	defer cleanEnv()
	
	cfg := config.LoadFromEnv()
	
	require.NotNil(t, cfg)
	
	// Verify custom values
	assert.Equal(t, 9090, cfg.Server.Port)
	assert.Equal(t, "127.0.0.1", cfg.Server.Host)
	assert.Equal(t, 60*time.Second, cfg.Server.ShutdownTimeout)
	assert.Equal(t, "/custom/path/db.sqlite", cfg.Database.Path)
	assert.Equal(t, 50, cfg.Database.MaxOpenConns)
	assert.Equal(t, 10, cfg.Database.MaxIdleConns)
	assert.Equal(t, 10*time.Minute, cfg.Database.ConnMaxLifetime)
	assert.True(t, cfg.Database.LogQueries)
	assert.Equal(t, "custom-secret", cfg.Auth.JWTSecret)
	assert.Equal(t, 48*time.Hour, cfg.Auth.TokenExpiration)
	assert.Equal(t, 60*time.Second, cfg.Auth.OTPWindow)
	assert.Equal(t, "debug", cfg.Logger.Level)
	assert.Equal(t, "/var/log/app.log", cfg.Logger.OutputPath)
	assert.Equal(t, []string{"http://example.com", "https://app.example.com"}, cfg.CORS.AllowedOrigins)
	assert.False(t, cfg.RateLimit.Enabled)
	assert.Equal(t, 200, cfg.RateLimit.RPS)
	assert.Equal(t, 300, cfg.RateLimit.BurstSize)
	assert.Equal(t, 2*time.Second, cfg.RateLimit.WindowTime)
}

// TestLoadFromEnv_InvalidValues tests that invalid values fall back to defaults
func TestLoadFromEnv_InvalidValues(t *testing.T) {
	cleanEnv()
	
	// Set invalid values
	os.Setenv("PORT", "invalid")
	os.Setenv("DB_MAX_OPEN_CONNS", "not-a-number")
	os.Setenv("DB_LOG_QUERIES", "maybe")
	os.Setenv("SERVER_SHUTDOWN_TIMEOUT", "invalid-duration")
	
	defer cleanEnv()
	
	cfg := config.LoadFromEnv()
	
	// Should fall back to defaults
	assert.Equal(t, 8081, cfg.Server.Port)
	assert.Equal(t, 25, cfg.Database.MaxOpenConns)
	assert.False(t, cfg.Database.LogQueries)
	assert.Equal(t, 30*time.Second, cfg.Server.ShutdownTimeout)
}

// TestLoadFromEnv_PartialConfiguration tests partial environment configuration
func TestLoadFromEnv_PartialConfiguration(t *testing.T) {
	cleanEnv()
	
	// Only set some values
	os.Setenv("PORT", "3000")
	os.Setenv("JWT_SECRET", "my-secret")
	
	defer cleanEnv()
	
	cfg := config.LoadFromEnv()
	
	// Custom values should be set
	assert.Equal(t, 3000, cfg.Server.Port)
	assert.Equal(t, "my-secret", cfg.Auth.JWTSecret)
	
	// Others should have defaults
	assert.Equal(t, "0.0.0.0", cfg.Server.Host)
	assert.Equal(t, "./waf.db", cfg.Database.Path)
	assert.Equal(t, "info", cfg.Logger.Level)
}

// TestLoadFromEnv_EmptyStringValues tests empty string environment variables
func TestLoadFromEnv_EmptyStringValues(t *testing.T) {
	cleanEnv()
	
	// Set empty strings
	os.Setenv("SERVER_HOST", "")
	os.Setenv("JWT_SECRET", "")
	
	defer cleanEnv()
	
	cfg := config.LoadFromEnv()
	
	// Should use defaults for empty strings
	assert.Equal(t, "0.0.0.0", cfg.Server.Host)
	assert.Equal(t, "your-secret-key", cfg.Auth.JWTSecret)
}

// TestLoadFromEnv_BooleanValues tests various boolean value formats
func TestLoadFromEnv_BooleanValues(t *testing.T) {
	testCases := []struct {
		name     string
		value    string
		expected bool
	}{
		{"true lowercase", "true", true},
		{"True capitalized", "True", true},
		{"TRUE uppercase", "TRUE", true},
		{"1", "1", true},
		{"false lowercase", "false", false},
		{"False capitalized", "False", false},
		{"FALSE uppercase", "FALSE", false},
		{"0", "0", false},
		{"invalid", "yes", false}, // default
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cleanEnv()
			os.Setenv("DB_LOG_QUERIES", tc.value)
			defer cleanEnv()
			
			cfg := config.LoadFromEnv()
			assert.Equal(t, tc.expected, cfg.Database.LogQueries)
		})
	}
}

// TestLoadFromEnv_DurationValues tests various duration formats
func TestLoadFromEnv_DurationValues(t *testing.T) {
	testCases := []struct {
		name     string
		value    string
		expected time.Duration
	}{
		{"seconds", "30s", 30 * time.Second},
		{"minutes", "5m", 5 * time.Minute},
		{"hours", "2h", 2 * time.Hour},
		{"mixed", "1h30m", 90 * time.Minute},
		{"milliseconds", "500ms", 500 * time.Millisecond},
		{"invalid", "invalid", 30 * time.Second}, // default
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cleanEnv()
			os.Setenv("SERVER_SHUTDOWN_TIMEOUT", tc.value)
			defer cleanEnv()
			
			cfg := config.LoadFromEnv()
			assert.Equal(t, tc.expected, cfg.Server.ShutdownTimeout)
		})
	}
}

// TestLoadFromEnv_IntegerValues tests various integer formats
func TestLoadFromEnv_IntegerValues(t *testing.T) {
	testCases := []struct {
		name     string
		value    string
		expected int
	}{
		{"positive", "100", 100},
		{"zero", "0", 0},
		{"negative", "-1", -1},
		{"large", "999999", 999999},
		{"invalid", "abc", 8081}, // default
		{"float", "3.14", 8081},  // default
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cleanEnv()
			os.Setenv("PORT", tc.value)
			defer cleanEnv()
			
			cfg := config.LoadFromEnv()
			assert.Equal(t, tc.expected, cfg.Server.Port)
		})
	}
}

// TestLoadFromEnv_StringSliceValues tests parsing comma-separated values
func TestLoadFromEnv_StringSliceValues(t *testing.T) {
	testCases := []struct {
		name     string
		value    string
		expected []string
	}{
		{
			"single value",
			"http://localhost:3000",
			[]string{"http://localhost:3000"},
		},
		{
			"multiple values",
			"http://localhost:3000,https://example.com,http://api.example.com",
			[]string{"http://localhost:3000", "https://example.com", "http://api.example.com"},
		},
		{
			"values with spaces",
			"http://localhost:3000 , https://example.com , http://api.example.com",
			[]string{"http://localhost:3000", "https://example.com", "http://api.example.com"},
		},
		{
			"empty string",
			"",
			[]string{"http://localhost:3000"}, // default
		},
		{
			"only commas",
			",,,",
			[]string{"http://localhost:3000"}, // default (all empty after trim)
		},
		{
			"mixed empty and values",
			"http://localhost:3000,,https://example.com",
			[]string{"http://localhost:3000", "https://example.com"},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cleanEnv()
			if tc.value != "" {
				os.Setenv("CORS_ALLOWED_ORIGINS", tc.value)
			}
			defer cleanEnv()
			
			cfg := config.LoadFromEnv()
			assert.Equal(t, tc.expected, cfg.CORS.AllowedOrigins)
		})
	}
}

// TestLoadFromEnv_MultipleLoads tests that multiple loads work correctly
func TestLoadFromEnv_MultipleLoads(t *testing.T) {
	cleanEnv()
	
	// First load with defaults
	cfg1 := config.LoadFromEnv()
	assert.Equal(t, 8081, cfg1.Server.Port)
	
	// Change environment
	os.Setenv("PORT", "9000")
	
	// Second load should pick up new value
	cfg2 := config.LoadFromEnv()
	assert.Equal(t, 9000, cfg2.Server.Port)
	
	// First config should remain unchanged
	assert.Equal(t, 8081, cfg1.Server.Port)
	
	cleanEnv()
}

// TestLoadFromEnv_StructureIntegrity tests that all config structures are properly initialized
func TestLoadFromEnv_StructureIntegrity(t *testing.T) {
	cleanEnv()
	
	cfg := config.LoadFromEnv()
	
	require.NotNil(t, cfg)
	
	// Verify all sub-structs are initialized (non-zero values)
	assert.NotZero(t, cfg.Server.Port)
	assert.NotEmpty(t, cfg.Server.Host)
	assert.NotZero(t, cfg.Server.ShutdownTimeout)
	
	assert.NotEmpty(t, cfg.Database.Path)
	assert.NotZero(t, cfg.Database.MaxOpenConns)
	assert.NotZero(t, cfg.Database.MaxIdleConns)
	assert.NotZero(t, cfg.Database.ConnMaxLifetime)
	
	assert.NotEmpty(t, cfg.Auth.JWTSecret)
	assert.NotZero(t, cfg.Auth.TokenExpiration)
	assert.NotZero(t, cfg.Auth.OTPWindow)
	
	assert.NotEmpty(t, cfg.Logger.Level)
	assert.NotEmpty(t, cfg.Logger.OutputPath)
	
	assert.NotEmpty(t, cfg.CORS.AllowedOrigins)
	assert.NotEmpty(t, cfg.CORS.AllowedMethods)
	assert.NotEmpty(t, cfg.CORS.AllowedHeaders)
	assert.NotZero(t, cfg.CORS.MaxAge)
	
	assert.NotZero(t, cfg.RateLimit.RPS)
	assert.NotZero(t, cfg.RateLimit.BurstSize)
	assert.NotZero(t, cfg.RateLimit.WindowTime)
}

// TestLoadFromEnv_RateLimitDisabled tests rate limit can be disabled
func TestLoadFromEnv_RateLimitDisabled(t *testing.T) {
	cleanEnv()
	
	os.Setenv("RATE_LIMIT_ENABLED", "false")
	defer cleanEnv()
	
	cfg := config.LoadFromEnv()
	
	assert.False(t, cfg.RateLimit.Enabled)
	// Other rate limit settings should still be set
	assert.NotZero(t, cfg.RateLimit.RPS)
	assert.NotZero(t, cfg.RateLimit.BurstSize)
}

// TestLoadFromEnv_EdgeCasePort tests edge case port numbers
func TestLoadFromEnv_EdgeCasePort(t *testing.T) {
	testCases := []struct {
		name     string
		value    string
		expected int
	}{
		{"min valid port", "1", 1},
		{"max valid port", "65535", 65535},
		{"privileged port", "80", 80},
		{"high port", "8080", 8080},
		{"zero port", "0", 0},
		{"negative port", "-1", -1}, // parsed as -1, validation elsewhere
		{"out of range", "99999", 99999}, // parsed, validation elsewhere
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cleanEnv()
			os.Setenv("PORT", tc.value)
			defer cleanEnv()
			
			cfg := config.LoadFromEnv()
			assert.Equal(t, tc.expected, cfg.Server.Port)
		})
	}
}

// TestLoadFromEnv_SpecialCharactersInStrings tests special characters in string values
func TestLoadFromEnv_SpecialCharactersInStrings(t *testing.T) {
	cleanEnv()
	
	os.Setenv("JWT_SECRET", "secret!@#$%^&*()_+-=[]{}|;:',.<>?/~`")
	os.Setenv("DB_PATH", "/path/to/database with spaces/file.db")
	os.Setenv("LOG_OUTPUT", "/var/log/app-$(date).log")
	
	defer cleanEnv()
	
	cfg := config.LoadFromEnv()
	
	assert.Equal(t, "secret!@#$%^&*()_+-=[]{}|;:',.<>?/~`", cfg.Auth.JWTSecret)
	assert.Equal(t, "/path/to/database with spaces/file.db", cfg.Database.Path)
	assert.Equal(t, "/var/log/app-$(date).log", cfg.Logger.OutputPath)
}

// TestLoadFromEnv_UnicodeValues tests unicode characters in configuration
func TestLoadFromEnv_UnicodeValues(t *testing.T) {
	cleanEnv()
	
	os.Setenv("JWT_SECRET", "密钥🔐secret日本語")
	os.Setenv("LOG_OUTPUT", "/var/log/приложение.log")
	
	defer cleanEnv()
	
	cfg := config.LoadFromEnv()
	
	assert.Equal(t, "密钥🔐secret日本語", cfg.Auth.JWTSecret)
	assert.Equal(t, "/var/log/приложение.log", cfg.Logger.OutputPath)
}

// TestLoadFromEnv_VeryLongValues tests very long string values
func TestLoadFromEnv_VeryLongValues(t *testing.T) {
	cleanEnv()

	// Create a very long secret (1000 characters)
	longSecret := ""
	for i := 0; i < 1000; i++ {
		longSecret += "a"
	}

	os.Setenv("JWT_SECRET", longSecret)

	defer cleanEnv()

	cfg := config.LoadFromEnv()

	assert.Len(t, cfg.Auth.JWTSecret, 1000)
	assert.Equal(t, longSecret, cfg.Auth.JWTSecret)
}

// TestLoadFromEnv_CORSOriginsSingleValue tests CORS with single origin
func TestLoadFromEnv_CORSOriginsSingleValue(t *testing.T) {
	cleanEnv()
	
	os.Setenv("CORS_ALLOWED_ORIGINS", "https://production.example.com")
	
	defer cleanEnv()
	
	cfg := config.LoadFromEnv()
	
	assert.Equal(t, []string{"https://production.example.com"}, cfg.CORS.AllowedOrigins)
}

// TestLoadFromEnv_CORSOriginsWildcard tests CORS with wildcard
func TestLoadFromEnv_CORSOriginsWildcard(t *testing.T) {
	cleanEnv()
	
	os.Setenv("CORS_ALLOWED_ORIGINS", "*")
	
	defer cleanEnv()
	
	cfg := config.LoadFromEnv()
	
	assert.Equal(t, []string{"*"}, cfg.CORS.AllowedOrigins)
}

// TestLoadFromEnv_ZeroValues tests explicit zero values
func TestLoadFromEnv_ZeroValues(t *testing.T) {
	cleanEnv()
	
	os.Setenv("DB_MAX_OPEN_CONNS", "0")
	os.Setenv("DB_MAX_IDLE_CONNS", "0")
	os.Setenv("RATE_LIMIT_RPS", "0")
	
	defer cleanEnv()
	
	cfg := config.LoadFromEnv()
	
	assert.Equal(t, 0, cfg.Database.MaxOpenConns)
	assert.Equal(t, 0, cfg.Database.MaxIdleConns)
	assert.Equal(t, 0, cfg.RateLimit.RPS)
}

// TestLoadFromEnv_CORSStaticValues tests that CORS static values are correct
func TestLoadFromEnv_CORSStaticValues(t *testing.T) {
	cleanEnv()
	
	cfg := config.LoadFromEnv()
	
	// These values are hardcoded and should always be the same
	assert.Equal(t, []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"}, cfg.CORS.AllowedMethods)
	assert.Equal(t, []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"}, cfg.CORS.AllowedHeaders)
	assert.Equal(t, []string{"Link"}, cfg.CORS.ExposedHeaders)
	assert.Equal(t, 300, cfg.CORS.MaxAge)
	assert.True(t, cfg.CORS.AllowCredentials)
}
