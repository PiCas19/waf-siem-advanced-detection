package auth

import (
	"errors"
	"time"
	
	"github.com/golang-jwt/jwt/v5"
)

var jwtSecret = []byte("your-secret-key-change-in-production")

// Claims represents JWT claims with user identification and role information.
//
// Fields:
//   - UserID (uint): User's database ID
//   - Email (string): User's email address
//   - Role (string): User's role (admin, operator, analyst, user)
//   - RegisteredClaims (jwt.RegisteredClaims): Standard JWT claims (exp, iat, etc.)
//
// Example Usage:
//   token, err := GenerateToken(user.ID, user.Email, user.Role)
//   claims, err := ValidateToken(tokenString)
//
// Thread Safety: Immutable after creation, safe for concurrent use.
//
// See Also: GenerateToken(), ValidateToken()
type Claims struct {
	UserID uint   `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

// GenerateToken creates a new JWT token
func GenerateToken(userID uint, email, role string) (string, error) {
	claims := Claims{
		UserID: userID,
		Email:  email,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// ValidateToken validates and parses a JWT token
func ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	
	if err != nil {
		return nil, err
	}
	
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}
	
	return nil, errors.New("invalid token")
}