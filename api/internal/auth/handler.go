package auth

import (
	"net/http"
	
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
)

type AuthHandler struct {
	db *gorm.DB
}

func NewAuthHandler(db *gorm.DB) *AuthHandler {
	return &AuthHandler{db: db}
}

type LoginRequest struct {
	Email string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type LoginOTPRequest struct {
	Email string `json:"email" binding:"required,email"`
	OTPCode string `json:"otp_code" binding:"required,len=6"`
	BackupCode string `json:"backup_code"`
}

type RegisterRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
	Name     string `json:"name" binding:"required"`
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
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	// Check if email exists
	var count int64
	h.db.Model(&models.User{}).Where("email = ?", req.Email).Count(&count)
	if count > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "Email already exists"})
		return
	}
	
	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}
	
	// Create user
	user := models.User{
		Email:        req.Email,
		PasswordHash: string(hashedPassword),
		Name:         req.Name,
		Role:         "user",
		Active:       true,
	}
	
	if err := h.db.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}
	
	// Generate token
	token, err := GenerateToken(user.ID, user.Email, user.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}
	
	c.JSON(http.StatusCreated, gin.H{
		"token": token,
		"user": gin.H{
			"id":    user.ID,
			"email": user.Email,
			"name":  user.Name,
			"role":  user.Role,
		},
	})
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

	// Update user with 2FA
	user.TwoFAEnabled = true
	user.OTPSecret = req.Secret
	// Backup codes were already generated in InitiateTwoFASetup
	// We need to recalculate them here since they're not persisted yet

	if err := h.db.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save 2FA setup"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "2FA setup completed successfully",
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