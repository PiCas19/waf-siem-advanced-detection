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
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/logger"
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
	ipAddress := c.ClientIP()
	logger.Log.WithFields(map[string]interface{}{
		"operation": "login_attempt",
		"ip_address": ipAddress,
	}).Info("Starting login process")

	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Log.WithFields(map[string]interface{}{
			"operation": "login_attempt",
			"ip_address": ipAddress,
		}).WithError(err).Error("Failed to bind login request")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	logger.Log.WithFields(map[string]interface{}{
		"operation": "login_attempt",
		"email": req.Email,
		"ip_address": ipAddress,
	}).Info("Processing login for user")

	// Find user
	var user models.User
	if err := h.db.Where("email = ?", req.Email).First(&user).Error; err != nil {
		// Log failed login attempt - user not found
		auditLog := models.AuditLog{
			UserEmail:    req.Email,
			Action:       "LOGIN",
			Category:     "AUTH",
			ResourceType: "user",
			ResourceID:   req.Email,
			Description:  "Login attempt failed - user not found",
			Status:       "failure",
			Error:        "User not found",
			IPAddress:    ipAddress,
			CreatedAt:    time.Now(),
		}
		h.db.Create(&auditLog)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		// Log failed login attempt - invalid password
		auditLog := models.AuditLog{
			UserID:       user.ID,
			UserEmail:    user.Email,
			Action:       "LOGIN",
			Category:     "AUTH",
			ResourceType: "user",
			ResourceID:   fmt.Sprintf("%d", user.ID),
			Description:  "Login attempt failed - invalid password",
			Status:       "failure",
			Error:        "Invalid password",
			IPAddress:    ipAddress,
			CreatedAt:    time.Now(),
		}
		h.db.Create(&auditLog)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Check if active
	if !user.Active {
		// Log failed login attempt - account disabled
		auditLog := models.AuditLog{
			UserID:       user.ID,
			UserEmail:    user.Email,
			Action:       "LOGIN",
			Category:     "AUTH",
			ResourceType: "user",
			ResourceID:   fmt.Sprintf("%d", user.ID),
			Description:  "Login attempt failed - account disabled",
			Status:       "failure",
			Error:        "Account disabled",
			IPAddress:    ipAddress,
			CreatedAt:    time.Now(),
		}
		h.db.Create(&auditLog)
		c.JSON(http.StatusForbidden, gin.H{"error": "Account disabled"})
		return
	}

	// Check if 2FA setup is mandatory
	if user.MustSetup2FA {
		// Generate temporary token to allow access to 2FA setup page
		token, err := GenerateToken(user.ID, user.Email, user.Role)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"requires_2fa_setup": true,
			"token":              token,
			"email":              user.Email,
			"message":            "Please set up 2FA before continuing",
			"user": gin.H{
				"id":    user.ID,
				"email": user.Email,
				"name":  user.Name,
				"role":  user.Role,
			},
		})
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
	logger.Log.WithFields(map[string]interface{}{
		"operation": "token_generation",
		"user_id": user.ID,
		"email": user.Email,
	}).Info("Generating authentication token")

	token, err := GenerateToken(user.ID, user.Email, user.Role)
	if err != nil {
		logger.Log.WithFields(map[string]interface{}{
			"operation": "token_generation",
			"user_id": user.ID,
			"email": user.Email,
		}).WithError(err).Error("Failed to generate authentication token")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	logger.Log.WithFields(map[string]interface{}{
		"operation": "login_success",
		"user_id": user.ID,
		"email": user.Email,
		"ip_address": ipAddress,
	}).Info("Login successful - token generated")

	// Log successful login (using direct DB create since we're in auth package)
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
	ipAddress := c.ClientIP()
	logger.Log.WithFields(map[string]interface{}{
		"operation": "2fa_verification",
		"ip_address": ipAddress,
	}).Info("Starting 2FA verification")

	var req LoginOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Log.WithFields(map[string]interface{}{
			"operation": "2fa_verification",
			"ip_address": ipAddress,
		}).WithError(err).Error("Failed to bind 2FA verification request")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	logger.Log.WithFields(map[string]interface{}{
		"operation": "2fa_verification",
		"email": req.Email,
		"ip_address": ipAddress,
		"has_otp": req.OTPCode != "",
		"has_backup": req.BackupCode != "",
	}).Info("Processing 2FA verification")

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
		// Log failed 2FA attempt - user not found
		auditLog := models.AuditLog{
			UserEmail:    req.Email,
			Action:       "LOGIN_2FA",
			Category:     "AUTH",
			ResourceType: "user",
			ResourceID:   req.Email,
			Description:  "2FA verification failed - user not found",
			Status:       "failure",
			Error:        "User not found",
			IPAddress:    ipAddress,
			CreatedAt:    time.Now(),
		}
		h.db.Create(&auditLog)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Verify OTP code or backup code
	var verified bool
	var codeType string
	if req.OTPCode != "" {
		verified = VerifyOTP(user.OTPSecret, req.OTPCode)
		codeType = "OTP"
	} else if req.BackupCode != "" {
		verified = VerifyBackupCode(&user, req.BackupCode)
		codeType = "BACKUP"
		if verified {
			// Save the updated backup codes
			h.db.Save(&user)
		}
	}

	if !verified {
		// Log failed 2FA attempt - invalid code
		auditLog := models.AuditLog{
			UserID:       user.ID,
			UserEmail:    user.Email,
			Action:       "LOGIN_2FA",
			Category:     "AUTH",
			ResourceType: "user",
			ResourceID:   fmt.Sprintf("%d", user.ID),
			Description:  fmt.Sprintf("2FA verification failed - invalid %s code", codeType),
			Status:       "failure",
			Error:        "Invalid 2FA code",
			IPAddress:    ipAddress,
			CreatedAt:    time.Now(),
		}
		h.db.Create(&auditLog)
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
	ipAddress := c.ClientIP()
	logger.Log.WithFields(map[string]interface{}{
		"operation": "admin_create_user",
		"ip_address": ipAddress,
	}).Info("Starting user creation by admin")

	var req struct {
		Email string `json:"email" binding:"required,email"`
		Name  string `json:"name" binding:"required"`
		Role  string `json:"role" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Log.WithFields(map[string]interface{}{
			"operation": "admin_create_user",
			"ip_address": ipAddress,
		}).WithError(err).Error("Failed to bind user creation request")
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get admin user ID from context
	adminUserID, _ := c.Get("user_id")
	adminUserEmail, _ := c.Get("user_email")

	logger.Log.WithFields(map[string]interface{}{
		"operation": "admin_create_user",
		"admin_id": adminUserID,
		"admin_email": adminUserEmail,
		"target_email": req.Email,
		"target_name": req.Name,
		"target_role": req.Role,
		"ip_address": ipAddress,
	}).Info("Processing user creation request")

	// validate role against supported roles
	if _, ok := RolePermissions[req.Role]; !ok {
		// Log failed user creation - invalid role
		auditLog := models.AuditLog{
			UserID:       adminUserID.(uint),
			UserEmail:    adminUserEmail.(string),
			Action:       "CREATE_USER",
			Category:     "USER_MANAGEMENT",
			ResourceType: "user",
			ResourceID:   req.Email,
			Description:  fmt.Sprintf("Failed to create user - invalid role '%s'", req.Role),
			Status:       "failure",
			Error:        "Invalid role",
			IPAddress:    ipAddress,
			CreatedAt:    time.Now(),
		}
		h.db.Create(&auditLog)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid role"})
		return
	}

	// check existing
	var existing models.User
	if err := h.db.Where("email = ?", req.Email).First(&existing).Error; err == nil {
		// Log failed user creation - email already exists
		auditLog := models.AuditLog{
			UserID:       adminUserID.(uint),
			UserEmail:    adminUserEmail.(string),
			Action:       "CREATE_USER",
			Category:     "USER_MANAGEMENT",
			ResourceType: "user",
			ResourceID:   req.Email,
			Description:  fmt.Sprintf("Failed to create user - email already exists"),
			Status:       "failure",
			Error:        "Email already exists",
			IPAddress:    ipAddress,
			CreatedAt:    time.Now(),
		}
		h.db.Create(&auditLog)
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
		// Log failed user creation - database error
		auditLog := models.AuditLog{
			UserID:       adminUserID.(uint),
			UserEmail:    adminUserEmail.(string),
			Action:       "CREATE_USER",
			Category:     "USER_MANAGEMENT",
			ResourceType: "user",
			ResourceID:   req.Email,
			Description:  fmt.Sprintf("Failed to create user"),
			Status:       "failure",
			Error:        "Database error",
			IPAddress:    ipAddress,
			CreatedAt:    time.Now(),
		}
		h.db.Create(&auditLog)
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

	// Log successful user creation
	auditLog := models.AuditLog{
		UserID:       adminUserID.(uint),
		UserEmail:    adminUserEmail.(string),
		Action:       "CREATE_USER",
		Category:     "USER_MANAGEMENT",
		ResourceType: "user",
		ResourceID:   fmt.Sprintf("%d", user.ID),
		Description:  fmt.Sprintf("Created user '%s' with role '%s' (email_sent: %v)", req.Name, req.Role, emailSent),
		Status:       "success",
		IPAddress:    ipAddress,
		CreatedAt:    time.Now(),
	}
	h.db.Create(&auditLog)

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
	// Mark that 2FA setup is mandatory for new user activation
	user.MustSetup2FA = true

	if err := h.db.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update password"})
		return
	}

	// Generate token for immediate access to 2FA setup
	token, err := GenerateToken(user.ID, user.Email, user.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	// Log password activation
	auditLog := models.AuditLog{
		UserID:       user.ID,
		UserEmail:    user.Email,
		Action:       "ACTIVATE_ACCOUNT",
		Category:     "AUTH",
		ResourceType: "user",
		ResourceID:   fmt.Sprintf("%d", user.ID),
		Description:  "User activated account by setting password",
		Status:       "success",
		IPAddress:    c.ClientIP(),
		CreatedAt:    time.Now(),
	}
	h.db.Create(&auditLog)

	c.JSON(http.StatusOK, gin.H{
		"requires_2fa_setup": true,
		"token":              token,
		"email":              user.Email,
		"message":            "Password set successfully. Please set up 2FA",
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
	user.MustSetup2FA = false  // Disable mandatory 2FA setup flag

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

// ForgotPassword handles password reset request (send email)
func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	ipAddress := c.ClientIP()
	logger.Log.WithFields(map[string]interface{}{
		"operation": "forgot_password",
		"ip_address": ipAddress,
	}).Info("Password reset request received")

	type ForgotPasswordRequest struct {
		Email string `json:"email" binding:"required,email"`
	}

	var req ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.Log.WithFields(map[string]interface{}{
			"operation": "forgot_password",
			"ip_address": ipAddress,
		}).WithError(err).Error("Failed to bind password reset request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email"})
		return
	}

	logger.Log.WithFields(map[string]interface{}{
		"operation": "forgot_password",
		"email": req.Email,
		"ip_address": ipAddress,
	}).Info("Processing password reset request")

	// Find user
	var user models.User
	if err := h.db.Where("email = ?", req.Email).First(&user).Error; err != nil {
		// For security, don't reveal if email exists
		c.JSON(http.StatusOK, gin.H{"message": "If the email exists, a reset link will be sent"})
		return
	}

	// Generate reset token (valid for 1 hour)
	resetToken, err := generateRandomToken(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate reset token"})
		return
	}

	// Hash the token for storage
	hashedToken, err := bcrypt.GenerateFromPassword([]byte(resetToken), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process token"})
		return
	}

	// Store reset token in database
	expiresAt := time.Now().Add(1 * time.Hour)
	if err := h.db.Model(&user).Update("password_reset_token", string(hashedToken)).
		Update("password_reset_expiry", expiresAt).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save reset token"})
		return
	}

	// Send reset email
	resetURL := fmt.Sprintf("https://%s/forgot-password?token=%s", c.Request.Host, resetToken)
	subject := "Password Reset Request"
	body := fmt.Sprintf(`
		<h2>Password Reset Request</h2>
		<p>You requested a password reset. Click the link below to reset your password:</p>
		<p><a href="%s">Reset Password</a></p>
		<p>This link will expire in 1 hour.</p>
		<p>If you didn't request this, ignore this email.</p>
	`, resetURL)

	if err := h.mailer.SendEmail(user.Email, subject, body); err != nil {
		// Log the error but don't expose it to client
		logger.Log.WithFields(map[string]interface{}{
			"email": user.Email,
		}).WithError(err).Error("Failed to send password reset email")
	}

	// Always return success for security
	c.JSON(http.StatusOK, gin.H{"message": "If the email exists, a reset link will be sent"})
}

// ResetPassword handles password reset (with token)
func (h *AuthHandler) ResetPassword(c *gin.Context) {
	type ResetPasswordRequest struct {
		Token       string `json:"token" binding:"required"`
		NewPassword string `json:"new_password" binding:"required,min=8"`
	}

	var req ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Find user with valid reset token
	var user models.User
	now := time.Now()
	if err := h.db.Where("password_reset_expiry > ? AND password_reset_token IS NOT NULL AND password_reset_token != ''", now).
		First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired reset token"})
		return
	}

	// Verify token
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordResetToken), []byte(req.Token)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid reset token"})
		return
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process password"})
		return
	}

	// Update password and clear reset token
	if err := h.db.Model(&user).
		Update("password_hash", string(hashedPassword)).
		Update("password_reset_token", "").
		Update("password_reset_expiry", time.Now()).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reset password"})
		return
	}

	// Log successful password reset
	auditLog := models.AuditLog{
		UserID:       user.ID,
		UserEmail:    user.Email,
		Action:       "PASSWORD_RESET",
		Category:     "AUTH",
		ResourceType: "user",
		ResourceID:   fmt.Sprintf("%d", user.ID),
		Description:  "Password reset successful",
		Status:       "success",
		IPAddress:    c.ClientIP(),
		CreatedAt:    time.Now(),
	}
	h.db.Create(&auditLog)

	c.JSON(http.StatusOK, gin.H{"message": "Password reset successfully"})
}

// Helper function to generate random token
func generateRandomToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}