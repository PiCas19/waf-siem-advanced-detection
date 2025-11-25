package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
)

// OTPConfig holds TOTP configuration for 2FA setup.
//
// Fields:
//   - Secret (string): Base32-encoded TOTP secret
//   - QRCodeURL (string): otpauth:// URL for QR code generation
//   - BackupCodes ([]string): Array of 8-digit backup codes
//
// Thread Safety: Immutable after creation, safe for concurrent use.
//
// See Also: SetupTwoFA(), VerifyOTP(), VerifyBackupCode()
type OTPConfig struct {
	Secret      string
	QRCodeURL   string
	BackupCodes []string
}

// GenerateOTPSecret generates a new TOTP secret for 2FA
func GenerateOTPSecret() (string, error) {
	// Generate 20 random bytes for the secret (RFC 4648 recommends 20 bytes for TOTP)
	// This will produce ~32 characters when base32 encoded
	randomBytes := make([]byte, 20)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Encode as base32 without padding (common for TOTP secrets)
	encoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	secret := encoder.EncodeToString(randomBytes)
	return secret, nil
}

// GenerateBackupCodes generates 10 backup codes (8 digits each)
func GenerateBackupCodes() ([]string, error) {
	codes := make([]string, 10)
	for i := 0; i < 10; i++ {
		// Generate random number between 10000000 and 99999999
		n, err := rand.Int(rand.Reader, big.NewInt(90000000))
		if err != nil {
			return nil, fmt.Errorf("failed to generate backup code: %w", err)
		}
		codes[i] = fmt.Sprintf("%08d", n.Int64()+10000000)
	}
	return codes, nil
}

// VerifyOTP verifies a TOTP code (6 digits)
func VerifyOTP(secret string, code string) bool {
	if len(code) != 6 {
		return false
	}

	// Get the current time in 30-second intervals
	now := time.Now()
	unixTime := now.Unix()
	counter := unixTime / 30

	// Check the current time window and adjacent windows (±2) to account for small clock skew
	for _, timeOffset := range []int64{-2, -1, 0, 1, 2} {
		if verifyTOTP(secret, code, counter+timeOffset) {
			return true
		}
	}

	return false
}

// verifyTOTP verifies TOTP for a specific counter value
func verifyTOTP(secret, code string, counter int64) bool {
	// Decode the secret
	decoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	decodedSecret, err := decoder.DecodeString(secret)
	if err != nil {
		return false
	}

	// Calculate HMAC-SHA1
	hash := calculateHMAC(decodedSecret, counter)

	// Dynamic truncation (RFC 4226)
	// Get last 4 bits to determine offset
	offset := hash[len(hash)-1] & 0xf

	// Extract 4 bytes starting at offset (with bounds checking)
	if int(offset) > len(hash)-4 {
		return false
	}

	// Properly extract 4 bytes as big-endian unsigned
	// Clear the high bit and mod by 1000000
	code32 := uint32(hash[offset]&0x7f)<<24 |
		uint32(hash[offset+1])<<16 |
		uint32(hash[offset+2])<<8 |
		uint32(hash[offset+3])

	codeValue := int(code32 % 1000000)

	generatedCode := fmt.Sprintf("%06d", codeValue)

	// Verify the code
	return generatedCode == code
}

// calculateHMAC calculates HMAC-SHA1
func calculateHMAC(key []byte, counter int64) []byte {
	// Convert counter to 8-byte big-endian
	counterBytes := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		counterBytes[i] = byte(counter & 0xff)
		counter >>= 8
	}

	h := hmac.New(sha1.New, key)
	h.Write(counterBytes)
	return h.Sum(nil)
}

// SetupTwoFA sets up 2FA for a user
func SetupTwoFA(user *models.User) (*OTPConfig, error) {
	secret, err := GenerateOTPSecret()
	if err != nil {
		return nil, fmt.Errorf("failed to generate OTP secret: %w", err)
	}

	backupCodes, err := GenerateBackupCodes()
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	// Store backup codes as JSON
	backupCodesJSON, err := json.Marshal(backupCodes)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal backup codes: %w", err)
	}

	user.OTPSecret = secret
	user.BackupCodes = string(backupCodesJSON)

	// Generate QR code URL for TOTP setup (for apps like Google Authenticator)
	qrCodeURL := fmt.Sprintf("otpauth://totp/WAF-Dashboard:%s?secret=%s&issuer=WAF-Dashboard", user.Email, secret)

	return &OTPConfig{
		Secret:      secret,
		QRCodeURL:   qrCodeURL,
		BackupCodes: backupCodes,
	}, nil
}

// VerifyBackupCode verifies and removes a backup code
func VerifyBackupCode(user *models.User, code string) bool {
	var backupCodes []string
	err := json.Unmarshal([]byte(user.BackupCodes), &backupCodes)
	if err != nil {
		return false
	}

	for i, bc := range backupCodes {
		if bc == code {
			// Remove used code
			backupCodes = append(backupCodes[:i], backupCodes[i+1:]...)
			backupCodesJSON, _ := json.Marshal(backupCodes)
			user.BackupCodes = string(backupCodesJSON)
			return true
		}
	}

	return false
}
