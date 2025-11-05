package auth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/mailer"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type AuthHandler struct {
	db *gorm.DB
	mailer *mailer.Mailer
}

func NewAuthHandler(db *gorm.DB, m *mailer.Mailer) *AuthHandler {
	return &AuthHandler{db: db, mailer: m}
}

type LoginRequest struct {
	Email string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type LoginOTPRequest struct {
	Email string `json:"email" binding:"required,email"`
	OTPCode string `json:"otp_code"`
	BackupCode string `json:"backup_code"`
}

type TwoFASetupRequest struct {
	OTPCode string `json:"otp_code" binding:"required,len=6"`
}

type TwoFASetupResponse struct {
	QRCodeURL   string   `json:"qr_code_url"`
	Secret      string   `json:"secret"`
	BackupCodes []string `json:"backup_codes"`
}

// Login handles user login (first step - password verification)
func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Find user
	var user models.User
	if err := h.db.Where("email = ?", req.Email).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Check if active
	if !user.Active {
		c.JSON(http.StatusForbidden, gin.H{"error": "Account disabled"})
		return
	}

	// Check if 2FA is enabled
	if user.TwoFAEnabled {
		// Return 2FA required response
		c.JSON(http.StatusOK, gin.H{
			"requires_2fa": true,
			"email":        user.Email,
			"message":      "Please provide your 2FA code",
		})
		return
	}

	// Generate token if 2FA is not enabled
	token, err := GenerateToken(user.ID, user.Email, user.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	// Log successful login (using direct DB create since we're in auth package)
	ipAddress := c.ClientIP()
	auditLog := models.AuditLog{
		UserID:       user.ID,
		UserEmail:    user.Email,
		Action:       "LOGIN",
		Category:     "AUTH",
		ResourceType: "user",
		ResourceID:   fmt.Sprintf("%d", user.ID),
		Description:  fmt.Sprintf("User logged in successfully"),
		Status:       "success",
		IPAddress:    ipAddress,
		CreatedAt:    time.Now(),
	}
	h.db.Create(&auditLog)

	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"user": gin.H{
			"id":    user.ID,
			"email": user.Email,
			"name":  user.Name,
			"role":  user.Role,
		},
	})
}

// VerifyOTPLogin handles the 2FA verification step
func (h *AuthHandler) VerifyOTPLogin(c *gin.Context) {
	var req LoginOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate that at least one of OTP code or backup code is provided
	if req.OTPCode == "" && req.BackupCode == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Either OTP code or backup code must be provided"})
		return
	}

	// Validate OTP code length if provided
	if req.OTPCode != "" && len(req.OTPCode) != 6 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "OTP code must be 6 digits"})
		return
	}

	// Find user
	var user models.User
	if err := h.db.Where("email = ?", req.Email).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Verify OTP code or backup code
	var verified bool
	if req.OTPCode != "" {
		verified = VerifyOTP(user.OTPSecret, req.OTPCode)
	} else if req.BackupCode != "" {
		verified = VerifyBackupCode(&user, req.BackupCode)
		if verified {
			// Save the updated backup codes
			h.db.Save(&user)
		}
	}

	if !verified {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid 2FA code"})
		return
	}

	// Generate token
	token, err := GenerateToken(user.ID, user.Email, user.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	// Log successful 2FA login
	ipAddress := c.ClientIP()
	auditLog := models.AuditLog{
		UserID:       user.ID,
		UserEmail:    user.Email,
		Action:       "LOGIN_2FA",
		Category:     "AUTH",
		ResourceType: "user",
		ResourceID:   fmt.Sprintf("%d", user.ID),
		Description:  fmt.Sprintf("User logged in successfully with 2FA"),
		Status:       "success",
		IPAddress:    ipAddress,
		CreatedAt:    time.Now(),
	}
	h.db.Create(&auditLog)

	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"user": gin.H{
			"id":    user.ID,
			"email": user.Email,
			"name":  user.Name,
			"role":  user.Role,
		},
	})
}

// Register handles user registration
func (h *AuthHandler) Register(c *gin.Context) {
	// Self-registration is disabled. Users must be created by an administrator.
	// This endpoint intentionally returns 403 to avoid accidental public registration.
	c.JSON(http.StatusForbidden, gin.H{"error": "Registration is disabled. Contact an administrator to create an account."})
}

// AdminCreateUser allows an admin to create a new user (invite flow)
func (h *AuthHandler) AdminCreateUser(c *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required,email"`
		Name  string `json:"name" binding:"required"`
		Role  string `json:"role" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// validate role against supported roles
	if _, ok := RolePermissions[req.Role]; !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role"})
		return
	}

	// check existing
	var existing models.User
	if err := h.db.Where("email = ?", req.Email).First(&existing).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Email already exists"})
		return
	}

	// generate temporary password (random)
	tempBytes := make([]byte, 8)
	if _, err := rand.Read(tempBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate password"})
		return
	}
	tempPassword := hex.EncodeToString(tempBytes)

	hashed, err := bcrypt.GenerateFromPassword([]byte(tempPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
		return
	}

	// generate reset/invite token
	tokenBytes := make([]byte, 24)
	if _, err := rand.Read(tokenBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}
	resetToken := hex.EncodeToString(tokenBytes)

	user := models.User{
		Email:               req.Email,
		Name:                req.Name,
		Role:                req.Role,
		Active:              false,
		PasswordHash:        string(hashed),
		PasswordResetToken:  resetToken,
		PasswordResetExpiry: time.Now().Add(24 * time.Hour),
	}

	if err := h.db.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create user"})
		return
	}

	// Build reset link. Prefer mailer SiteURL for absolute link, otherwise relative.
	resetLink := fmt.Sprintf("/set-password?token=%s", resetToken)
	if h.mailer != nil && h.mailer.SiteURL != "" {
		resetLink = fmt.Sprintf("%s/set-password?token=%s", strings.TrimRight(h.mailer.SiteURL, "/"), resetToken)
	}

	emailSent := false
	if h.mailer != nil {
		if err := h.mailer.SendInvite(req.Email, req.Name, resetLink, tempPassword); err == nil {
			emailSent = true
		}
		// log and continue
	}

	// Return created response. In production avoid returning tokens; for now include reset_link for convenience if email not sent.
	resp := gin.H{"message": "User created", "email_sent": emailSent}
	if !emailSent {
		resp["temp_password"] = tempPassword
		resp["reset_token"] = resetToken
		resp["reset_link"] = resetLink
	}
	c.JSON(http.StatusCreated, resp)
}

// SetPasswordWithToken allows a user to set their password using the invite/reset token
func (h *AuthHandler) SetPasswordWithToken(c *gin.Context) {
	var req struct {
		Token       string `json:"token" binding:"required"`
		NewPassword string `json:"new_password" binding:"required,min=8"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.User
	if err := h.db.Where("password_reset_token = ?", req.Token).First(&user).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid token"})
		return
	}

	if time.Now().After(user.PasswordResetExpiry) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token expired"})
		return
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
		return
	}

	user.PasswordHash = string(hashed)
	user.PasswordResetToken = ""
	user.PasswordResetExpiry = time.Time{}
	user.Active = true

	if err := h.db.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password set successfully"})
}

// InitiateTwoFASetup initiates 2FA setup for authenticated user
func (h *AuthHandler) InitiateTwoFASetup(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var user models.User
	if err := h.db.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Generate new 2FA setup
	otpConfig, err := SetupTwoFA(&user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to setup 2FA"})
		return
	}

	// Don't save to DB yet - wait for user to confirm with OTP code
	// We'll send temporary OTP setup to user
	c.JSON(http.StatusOK, TwoFASetupResponse{
		QRCodeURL:   otpConfig.QRCodeURL,
		Secret:      otpConfig.Secret,
		BackupCodes: otpConfig.BackupCodes,
	})
}

// CompleteTwoFASetup completes 2FA setup after user confirms OTP
func (h *AuthHandler) CompleteTwoFASetup(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req struct {
		Secret  string `json:"secret" binding:"required"`
		OTPCode string `json:"otp_code" binding:"required,len=6"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify OTP code
	if !VerifyOTP(req.Secret, req.OTPCode) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid OTP code"})
		return
	}

	var user models.User
	if err := h.db.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Generate fresh backup codes
	backupCodes, err := GenerateBackupCodes()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate backup codes"})
		return
	}

	// Encode backup codes as JSON
	backupCodesJSON, err := json.Marshal(backupCodes)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process backup codes"})
		return
	}

	// Update user with 2FA and activate account
	user.TwoFAEnabled = true
	user.OTPSecret = req.Secret
	user.BackupCodes = string(backupCodesJSON)
	user.Active = true

	if err := h.db.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save 2FA setup"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "2FA setup completed successfully",
		"backup_codes": backupCodes,
	})
}

// DisableTwoFA disables 2FA for authenticated user
func (h *AuthHandler) DisableTwoFA(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req struct {
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.User
	if err := h.db.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Verify password before disabling 2FA
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid password"})
		return
	}

	// Disable 2FA
	user.TwoFAEnabled = false
	user.OTPSecret = ""
	user.BackupCodes = ""

	if err := h.db.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to disable 2FA"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "2FA disabled successfully",
	})
}

// ChangePassword allows an authenticated user to change their password
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password" binding:"required"`
		NewPassword     string `json:"new_password" binding:"required,min=8"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.User
	if err := h.db.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Verify current password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.CurrentPassword)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid current password"})
		return
	}

	// Hash new password
	hashed, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash new password"})
		return
	}

	user.PasswordHash = string(hashed)
	if err := h.db.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password updated successfully"})
}