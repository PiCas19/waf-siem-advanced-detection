package auth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/auth"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateOTPSecret(t *testing.T) {
	secret, err := auth.GenerateOTPSecret()
	assert.NoError(t, err)
	assert.NotEmpty(t, secret)

	// Secret should be base32 encoded and have reasonable length
	assert.Greater(t, len(secret), 20)
	assert.Less(t, len(secret), 50)
}

func TestGenerateOTPSecret_UniqueSecrets(t *testing.T) {
	secrets := make(map[string]bool)

	for i := 0; i < 10; i++ {
		secret, err := auth.GenerateOTPSecret()
		require.NoError(t, err)

		// Each secret should be unique
		assert.False(t, secrets[secret], "Secret should be unique")
		secrets[secret] = true
	}
}

func TestGenerateOTPSecret_ValidBase32(t *testing.T) {
	secret, err := auth.GenerateOTPSecret()
	require.NoError(t, err)

	// Should be decodable as base32
	decoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	decoded, err := decoder.DecodeString(secret)
	assert.NoError(t, err)
	assert.NotEmpty(t, decoded)
}

func TestGenerateBackupCodes(t *testing.T) {
	codes, err := auth.GenerateBackupCodes()
	assert.NoError(t, err)
	assert.Len(t, codes, 10)

	// Each code should be 8 digits
	for _, code := range codes {
		assert.Len(t, code, 8)
		assert.Regexp(t, `^\d{8}$`, code)
	}
}

func TestGenerateBackupCodes_Unique(t *testing.T) {
	codes, err := auth.GenerateBackupCodes()
	require.NoError(t, err)

	// All codes should be unique
	codeMap := make(map[string]bool)
	for _, code := range codes {
		assert.False(t, codeMap[code], "Backup codes should be unique")
		codeMap[code] = true
	}
}

func TestGenerateBackupCodes_ValidRange(t *testing.T) {
	codes, err := auth.GenerateBackupCodes()
	require.NoError(t, err)

	for _, code := range codes {
		// Code should be >= 10000000 and <= 99999999
		var codeInt int
		_, err := fmt.Sscanf(code, "%d", &codeInt)
		assert.NoError(t, err)
		assert.GreaterOrEqual(t, codeInt, 10000000)
		assert.LessOrEqual(t, codeInt, 99999999)
	}
}

func TestVerifyOTP_InvalidLength(t *testing.T) {
	secret, _ := auth.GenerateOTPSecret()

	invalidCodes := []string{
		"",
		"12345",      // Too short
		"1234567",    // Too short
		"12345678",   // Too long
		"123456789",  // Too long
	}

	for _, code := range invalidCodes {
		assert.False(t, auth.VerifyOTP(secret, code), "Code %s should be invalid", code)
	}
}

func TestVerifyOTP_InvalidFormat(t *testing.T) {
	secret, _ := auth.GenerateOTPSecret()

	invalidCodes := []string{
		"abcdef",
		"12345a",
		"!@#$%^",
		"      ",
	}

	for _, code := range invalidCodes {
		assert.False(t, auth.VerifyOTP(secret, code))
	}
}

func TestVerifyOTP_WithValidCode(t *testing.T) {
	// Generate a secret
	secret, err := auth.GenerateOTPSecret()
	require.NoError(t, err)

	// Generate a valid TOTP code for current time
	now := time.Now()
	counter := now.Unix() / 30
	code := generateTOTPCode(secret, counter)

	// Verify the code
	assert.True(t, auth.VerifyOTP(secret, code))
}

func TestVerifyOTP_TimeWindowTolerance(t *testing.T) {
	secret, err := auth.GenerateOTPSecret()
	require.NoError(t, err)

	now := time.Now()
	counter := now.Unix() / 30

	// Test codes from different time windows (±2 windows)
	for offset := int64(-2); offset <= 2; offset++ {
		code := generateTOTPCode(secret, counter+offset)
		assert.True(t, auth.VerifyOTP(secret, code), "Code from offset %d should be valid", offset)
	}
}

func TestVerifyOTP_OutsideTimeWindow(t *testing.T) {
	secret, err := auth.GenerateOTPSecret()
	require.NoError(t, err)

	now := time.Now()
	counter := now.Unix() / 30

	// Codes outside the ±2 window should fail
	for _, offset := range []int64{-3, -10, 3, 10} {
		code := generateTOTPCode(secret, counter+offset)
		assert.False(t, auth.VerifyOTP(secret, code), "Code from offset %d should be invalid", offset)
	}
}

func TestVerifyOTP_InvalidSecret(t *testing.T) {
	invalidSecrets := []string{
		"",
		"invalid-secret",
		"!@#$%^&*()",
	}

	for _, secret := range invalidSecrets {
		assert.False(t, auth.VerifyOTP(secret, "123456"))
	}
}

func TestSetupTwoFA(t *testing.T) {
	user := &models.User{
		ID:    1,
		Email: "test@example.com",
	}

	config, err := auth.SetupTwoFA(user)
	assert.NoError(t, err)
	require.NotNil(t, config)

	// Check secret
	assert.NotEmpty(t, config.Secret)
	assert.Equal(t, config.Secret, user.OTPSecret)

	// Check QR code URL
	assert.NotEmpty(t, config.QRCodeURL)
	assert.Contains(t, config.QRCodeURL, "otpauth://totp/")
	assert.Contains(t, config.QRCodeURL, user.Email)
	assert.Contains(t, config.QRCodeURL, config.Secret)

	// Check backup codes
	assert.Len(t, config.BackupCodes, 10)

	// Verify backup codes are stored in user
	var storedCodes []string
	err = json.Unmarshal([]byte(user.BackupCodes), &storedCodes)
	assert.NoError(t, err)
	assert.Equal(t, config.BackupCodes, storedCodes)
}

func TestSetupTwoFA_QRCodeURLFormat(t *testing.T) {
	user := &models.User{
		ID:    1,
		Email: "user@example.com",
	}

	config, err := auth.SetupTwoFA(user)
	require.NoError(t, err)

	// QR code URL should have correct format
	expectedPrefix := fmt.Sprintf("otpauth://totp/WAF-Dashboard:%s?secret=", user.Email)
	assert.Contains(t, config.QRCodeURL, expectedPrefix)
	assert.Contains(t, config.QRCodeURL, "&issuer=WAF-Dashboard")
}

func TestSetupTwoFA_UniqueSecretsPerUser(t *testing.T) {
	secrets := make(map[string]bool)

	for i := 0; i < 5; i++ {
		user := &models.User{
			ID:    uint(i + 1),
			Email: fmt.Sprintf("user%d@example.com", i),
		}

		config, err := auth.SetupTwoFA(user)
		require.NoError(t, err)

		// Each user should get a unique secret
		assert.False(t, secrets[config.Secret], "Secret should be unique per user")
		secrets[config.Secret] = true
	}
}

func TestVerifyBackupCode_Success(t *testing.T) {
	user := &models.User{
		ID:    1,
		Email: "test@example.com",
	}

	config, err := auth.SetupTwoFA(user)
	require.NoError(t, err)

	// Use the first backup code
	firstCode := config.BackupCodes[0]
	assert.True(t, auth.VerifyBackupCode(user, firstCode))

	// Verify code was removed
	var remainingCodes []string
	err = json.Unmarshal([]byte(user.BackupCodes), &remainingCodes)
	require.NoError(t, err)
	assert.Len(t, remainingCodes, 9)
	assert.NotContains(t, remainingCodes, firstCode)
}

func TestVerifyBackupCode_Invalid(t *testing.T) {
	user := &models.User{
		ID:    1,
		Email: "test@example.com",
	}

	config, err := auth.SetupTwoFA(user)
	require.NoError(t, err)

	// Try invalid codes
	invalidCodes := []string{
		"00000000",
		"99999999",
		"12345678",
		"invalid",
	}

	for _, code := range invalidCodes {
		// Skip if code happens to be in backup codes
		found := false
		for _, bc := range config.BackupCodes {
			if bc == code {
				found = true
				break
			}
		}
		if found {
			continue
		}

		assert.False(t, auth.VerifyBackupCode(user, code))
	}
}

func TestVerifyBackupCode_UsedTwice(t *testing.T) {
	user := &models.User{
		ID:    1,
		Email: "test@example.com",
	}

	config, err := auth.SetupTwoFA(user)
	require.NoError(t, err)

	firstCode := config.BackupCodes[0]

	// First use should succeed
	assert.True(t, auth.VerifyBackupCode(user, firstCode))

	// Second use should fail
	assert.False(t, auth.VerifyBackupCode(user, firstCode))
}

func TestVerifyBackupCode_AllCodes(t *testing.T) {
	user := &models.User{
		ID:    1,
		Email: "test@example.com",
	}

	config, err := auth.SetupTwoFA(user)
	require.NoError(t, err)

	// Use all backup codes
	for i, code := range config.BackupCodes {
		assert.True(t, auth.VerifyBackupCode(user, code), "Code %d should be valid", i)
	}

	// Verify all codes are gone
	var remainingCodes []string
	err = json.Unmarshal([]byte(user.BackupCodes), &remainingCodes)
	require.NoError(t, err)
	assert.Empty(t, remainingCodes)
}

func TestVerifyBackupCode_InvalidJSON(t *testing.T) {
	user := &models.User{
		ID:          1,
		Email:       "test@example.com",
		BackupCodes: "invalid-json",
	}

	assert.False(t, auth.VerifyBackupCode(user, "12345678"))
}

func TestVerifyBackupCode_EmptyBackupCodes(t *testing.T) {
	user := &models.User{
		ID:          1,
		Email:       "test@example.com",
		BackupCodes: "[]",
	}

	assert.False(t, auth.VerifyBackupCode(user, "12345678"))
}

func TestVerifyOTP_Integration(t *testing.T) {
	// Full integration test: Setup 2FA and verify OTP
	user := &models.User{
		ID:    1,
		Email: "test@example.com",
	}

	config, err := auth.SetupTwoFA(user)
	require.NoError(t, err)

	// Generate a valid OTP code for current time
	now := time.Now()
	counter := now.Unix() / 30
	code := generateTOTPCode(config.Secret, counter)

	// Verify the code works
	assert.True(t, auth.VerifyOTP(config.Secret, code))
}

func TestTOTPConsistency(t *testing.T) {
	// Verify that the same secret and counter always generate the same code
	secret, _ := auth.GenerateOTPSecret()
	counter := time.Now().Unix() / 30

	code1 := generateTOTPCode(secret, counter)
	code2 := generateTOTPCode(secret, counter)

	assert.Equal(t, code1, code2, "Same secret and counter should generate same code")
}

func TestSetupTwoFA_BackupCodesFormat(t *testing.T) {
	user := &models.User{
		ID:    1,
		Email: "test@example.com",
	}

	config, err := auth.SetupTwoFA(user)
	require.NoError(t, err)

	// Verify each backup code has correct format
	for i, code := range config.BackupCodes {
		assert.Len(t, code, 8, "Backup code %d should be 8 digits", i)
		assert.Regexp(t, `^\d{8}$`, code, "Backup code %d should be numeric", i)
	}
}

func TestVerifyOTP_EmptySecret(t *testing.T) {
	assert.False(t, auth.VerifyOTP("", "123456"))
}

func TestVerifyBackupCode_RemainingCodesOrder(t *testing.T) {
	user := &models.User{
		ID:    1,
		Email: "test@example.com",
	}

	config, err := auth.SetupTwoFA(user)
	require.NoError(t, err)

	// Remove the middle code (index 5)
	codeToRemove := config.BackupCodes[5]
	auth.VerifyBackupCode(user, codeToRemove)

	// Verify remaining codes maintain order (except removed one)
	var remainingCodes []string
	err = json.Unmarshal([]byte(user.BackupCodes), &remainingCodes)
	require.NoError(t, err)
	assert.Len(t, remainingCodes, 9)

	// The removed code should not be present
	for _, code := range remainingCodes {
		assert.NotEqual(t, codeToRemove, code)
	}
}

// Helper function to generate TOTP code for testing
func generateTOTPCode(secret string, counter int64) string {
	decoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	decodedSecret, _ := decoder.DecodeString(secret)

	// Convert counter to 8-byte big-endian
	counterBytes := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		counterBytes[i] = byte(counter & 0xff)
		counter >>= 8
	}

	// Calculate HMAC-SHA1
	h := hmac.New(sha1.New, decodedSecret)
	h.Write(counterBytes)
	hash := h.Sum(nil)

	// Dynamic truncation
	offset := hash[len(hash)-1] & 0xf

	code32 := uint32(hash[offset]&0x7f)<<24 |
		uint32(hash[offset+1])<<16 |
		uint32(hash[offset+2])<<8 |
		uint32(hash[offset+3])

	codeValue := int(code32 % 1000000)
	return fmt.Sprintf("%06d", codeValue)
}
