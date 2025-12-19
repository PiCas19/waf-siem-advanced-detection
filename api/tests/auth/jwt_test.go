package auth

import (
	"testing"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/auth"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateToken(t *testing.T) {
	userID := uint(1)
	email := "test@example.com"
	role := "admin"

	token, err := auth.GenerateToken(userID, email, role)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// Verify token can be parsed
	_, err = jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte("your-secret-key-change-in-production"), nil
	})
	assert.NoError(t, err)
}

func TestGenerateToken_DifferentRoles(t *testing.T) {
	roles := []string{"admin", "operator", "analyst", "user"}

	for _, role := range roles {
		token, err := auth.GenerateToken(1, "test@example.com", role)
		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		claims, err := auth.ValidateToken(token)
		assert.NoError(t, err)
		assert.Equal(t, role, claims.Role)
	}
}

func TestGenerateToken_DifferentUserIDs(t *testing.T) {
	userIDs := []uint{1, 100, 999, 10000}

	for _, userID := range userIDs {
		token, err := auth.GenerateToken(userID, "test@example.com", "admin")
		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		claims, err := auth.ValidateToken(token)
		assert.NoError(t, err)
		assert.Equal(t, userID, claims.UserID)
	}
}

func TestValidateToken_Success(t *testing.T) {
	userID := uint(123)
	email := "test@example.com"
	role := "admin"

	token, err := auth.GenerateToken(userID, email, role)
	require.NoError(t, err)

	claims, err := auth.ValidateToken(token)
	assert.NoError(t, err)
	require.NotNil(t, claims)
	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, email, claims.Email)
	assert.Equal(t, role, claims.Role)
}

func TestValidateToken_InvalidToken(t *testing.T) {
	invalidToken := "invalid.token.string"

	claims, err := auth.ValidateToken(invalidToken)
	assert.Error(t, err)
	assert.Nil(t, claims)
}

func TestValidateToken_MalformedToken(t *testing.T) {
	malformedTokens := []string{
		"",
		"not-a-jwt",
		"header.payload",
		"header.payload.signature.extra",
	}

	for _, token := range malformedTokens {
		claims, err := auth.ValidateToken(token)
		assert.Error(t, err)
		assert.Nil(t, claims)
	}
}

func TestValidateToken_ExpiredToken(t *testing.T) {
	// Create a token that's already expired
	claims := auth.Claims{
		UserID: 1,
		Email:  "test@example.com",
		Role:   "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)), // Expired 1 hour ago
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte("your-secret-key-change-in-production"))
	require.NoError(t, err)

	validatedClaims, err := auth.ValidateToken(tokenString)
	assert.Error(t, err)
	assert.Nil(t, validatedClaims)
}

func TestValidateToken_WrongSignature(t *testing.T) {
	// Create token with different secret
	claims := auth.Claims{
		UserID: 1,
		Email:  "test@example.com",
		Role:   "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte("wrong-secret-key"))
	require.NoError(t, err)

	validatedClaims, err := auth.ValidateToken(tokenString)
	assert.Error(t, err)
	assert.Nil(t, validatedClaims)
}

func TestTokenExpiration(t *testing.T) {
	token, err := auth.GenerateToken(1, "test@example.com", "admin")
	require.NoError(t, err)

	claims, err := auth.ValidateToken(token)
	require.NoError(t, err)

	// Check that token expires in approximately 24 hours
	expiresAt := claims.ExpiresAt.Time
	issuedAt := claims.IssuedAt.Time
	duration := expiresAt.Sub(issuedAt)

	assert.InDelta(t, 24*time.Hour, duration, float64(time.Second))
}

func TestTokenIssuedAt(t *testing.T) {
	beforeGeneration := time.Now()
	token, err := auth.GenerateToken(1, "test@example.com", "admin")
	afterGeneration := time.Now()

	require.NoError(t, err)

	claims, err := auth.ValidateToken(token)
	require.NoError(t, err)

	// Verify IssuedAt is within generation timeframe
	assert.True(t, claims.IssuedAt.Time.After(beforeGeneration.Add(-time.Second)))
	assert.True(t, claims.IssuedAt.Time.Before(afterGeneration.Add(time.Second)))
}

func TestValidateToken_EmptyFields(t *testing.T) {
	// Generate token with empty fields
	token, err := auth.GenerateToken(0, "", "")
	require.NoError(t, err)

	claims, err := auth.ValidateToken(token)
	assert.NoError(t, err)
	assert.Equal(t, uint(0), claims.UserID)
	assert.Equal(t, "", claims.Email)
	assert.Equal(t, "", claims.Role)
}

func TestGenerateAndValidateToken_SpecialCharacters(t *testing.T) {
	// Test with special characters in email
	email := "test+special@example.com"
	role := "admin"

	token, err := auth.GenerateToken(1, email, role)
	require.NoError(t, err)

	claims, err := auth.ValidateToken(token)
	assert.NoError(t, err)
	assert.Equal(t, email, claims.Email)
}

func TestGenerateToken_ConsistentFormat(t *testing.T) {
	// Generate multiple tokens and verify they all have JWT format (3 parts separated by dots)
	for i := 0; i < 10; i++ {
		token, err := auth.GenerateToken(uint(i), "test@example.com", "admin")
		require.NoError(t, err)

		// JWT should have exactly 3 parts
		parts := 0
		for _, c := range token {
			if c == '.' {
				parts++
			}
		}
		assert.Equal(t, 2, parts, "JWT should have 2 dots (3 parts)")
	}
}

func TestValidateToken_ValidTokenStaysValid(t *testing.T) {
	token, err := auth.GenerateToken(1, "test@example.com", "admin")
	require.NoError(t, err)

	// Validate token multiple times
	for i := 0; i < 5; i++ {
		claims, err := auth.ValidateToken(token)
		assert.NoError(t, err)
		assert.NotNil(t, claims)
		assert.Equal(t, uint(1), claims.UserID)
	}
}
