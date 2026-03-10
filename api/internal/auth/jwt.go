package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	jwtSecret              = []byte("your-secret-key-change-in-production")
	accessTokenExpiration  = 24 * time.Hour
	refreshTokenExpiration = 7 * 24 * time.Hour
)

// InitJWTConfig initializes the JWT configuration from the application config.
func InitJWTConfig(secret string, accessExp, refreshExp time.Duration) {
	jwtSecret = []byte(secret)
	accessTokenExpiration = accessExp
	refreshTokenExpiration = refreshExp
}

// Claims represents JWT claims with user identification and role information.
type Claims struct {
	UserID    uint   `json:"user_id"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	TokenType string `json:"token_type,omitempty"`
	jwt.RegisteredClaims
}

// GenerateToken creates a new access JWT token
func GenerateToken(userID uint, email, role string) (string, error) {
	claims := Claims{
		UserID:    userID,
		Email:     email,
		Role:      role,
		TokenType: "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(accessTokenExpiration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// GenerateRefreshToken creates a new refresh JWT token.
// Returns the token string, its JTI (JWT ID used for rotation detection), and any error.
func GenerateRefreshToken(userID uint, email, role string) (tokenString, jti string, err error) {
	jtiBytes := make([]byte, 16)
	if _, err = rand.Read(jtiBytes); err != nil {
		return
	}
	jti = hex.EncodeToString(jtiBytes)

	claims := Claims{
		UserID:    userID,
		Email:     email,
		Role:      role,
		TokenType: "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(refreshTokenExpiration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err = token.SignedString(jwtSecret)
	return
}

// ValidateToken validates and parses an access JWT token.
// Returns an error if the token is a refresh token.
func ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		// Reject refresh tokens used as access tokens.
		// Allow legacy tokens without token_type for backward compatibility.
		if claims.TokenType != "" && claims.TokenType != "access" {
			return nil, errors.New("invalid token type")
		}
		return claims, nil
	}
	return nil, errors.New("invalid token")
}

// ValidateRefreshToken validates and parses a refresh JWT token.
// Returns an error if the token is not a refresh token.
func ValidateRefreshToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		if claims.TokenType != "refresh" {
			return nil, errors.New("invalid token type: expected refresh token")
		}
		return claims, nil
	}
	return nil, errors.New("invalid token")
}
