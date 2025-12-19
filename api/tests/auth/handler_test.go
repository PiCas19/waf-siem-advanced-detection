package auth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/auth"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/logger"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/mailer"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// init initializes the logger for tests
func init() {
	if err := logger.InitLogger("error", "stdout"); err != nil {
		panic("Failed to initialize logger: " + err.Error())
	}
	gin.SetMode(gin.TestMode)
}

// setupTestDB creates an in-memory database for testing
func setupTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&models.User{}, &models.AuditLog{})
	require.NoError(t, err)

	return db
}

// createTestUser creates a user in the database for testing
func createTestUser(t *testing.T, db *gorm.DB, email, password, role string, active, twoFAEnabled bool) models.User {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	require.NoError(t, err)

	user := models.User{
		Email:        email,
		Name:         "Test User",
		Role:         role,
		PasswordHash: string(hashedPassword),
		Active:       active,
		TwoFAEnabled: twoFAEnabled,
	}

	result := db.Create(&user)
	require.NoError(t, result.Error)

	return user
}

// mockMailer is a mock implementation of mailer for testing
type mockMailer struct {
	sentEmails []sentEmail
}

type sentEmail struct {
	to      string
	subject string
	body    string
}

func (m *mockMailer) SendEmail(to, subject, body string) error {
	m.sentEmails = append(m.sentEmails, sentEmail{to: to, subject: subject, body: body})
	return nil
}

func newMockMailer() *mockMailer {
	return &mockMailer{
		sentEmails: make([]sentEmail, 0),
	}
}

// TestRegister tests that registration is disabled
func TestRegister(t *testing.T) {
	db := setupTestDB(t)

	var mailerInterface *mailer.Mailer
	handler := auth.NewAuthHandler(db, mailerInterface)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	handler.Register(c)

	assert.Equal(t, http.StatusForbidden, w.Code)
	
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Contains(t, response["error"], "Registration is disabled")
}

// TestLogin_Success tests successful login without 2FA
func TestLogin_Success(t *testing.T) {
	db := setupTestDB(t)

	var mailerInterface *mailer.Mailer
	handler := auth.NewAuthHandler(db, mailerInterface)

	// Create test user
	createTestUser(t, db, "test@example.com", "password123", "user", true, false)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	loginReq := map[string]string{
		"email":    "test@example.com",
		"password": "password123",
	}
	body, _ := json.Marshal(loginReq)
	c.Request = httptest.NewRequest("POST", "/login", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.Login(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.NotEmpty(t, response["token"])
}

// TestLogin_UserNotFound tests login with non-existent user
func TestLogin_UserNotFound(t *testing.T) {
	db := setupTestDB(t)
	
	var mailerInterface *mailer.Mailer
	handler := auth.NewAuthHandler(db, mailerInterface)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	loginReq := map[string]string{
		"email":    "nonexistent@example.com",
		"password": "password123",
	}
	body, _ := json.Marshal(loginReq)
	c.Request = httptest.NewRequest("POST", "/login", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.Login(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestLogin_InvalidPassword tests login with wrong password
func TestLogin_InvalidPassword(t *testing.T) {
	db := setupTestDB(t)
	
	var mailerInterface *mailer.Mailer
	handler := auth.NewAuthHandler(db, mailerInterface)

	createTestUser(t, db, "test@example.com", "correctpassword", "user", true, false)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	loginReq := map[string]string{
		"email":    "test@example.com",
		"password": "wrongpassword",
	}
	body, _ := json.Marshal(loginReq)
	c.Request = httptest.NewRequest("POST", "/login", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.Login(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestLogin_AccountDisabled tests login with inactive account
func TestLogin_AccountDisabled(t *testing.T) {
	db := setupTestDB(t)
	
	var mailerInterface *mailer.Mailer
	handler := auth.NewAuthHandler(db, mailerInterface)

	createTestUser(t, db, "test@example.com", "password123", "user", false, false)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	loginReq := map[string]string{
		"email":    "test@example.com",
		"password": "password123",
	}
	body, _ := json.Marshal(loginReq)
	c.Request = httptest.NewRequest("POST", "/login", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.Login(c)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// TestLogin_Requires2FA tests login when 2FA is enabled
func TestLogin_Requires2FA(t *testing.T) {
	db := setupTestDB(t)
	
	var mailerInterface *mailer.Mailer
	handler := auth.NewAuthHandler(db, mailerInterface)

	user := createTestUser(t, db, "test@example.com", "password123", "user", true, true)

	// Set 2FA secret
	user.OTPSecret = "TESTSECRET123456"
	db.Save(&user)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	loginReq := map[string]string{
		"email":    "test@example.com",
		"password": "password123",
	}
	body, _ := json.Marshal(loginReq)
	c.Request = httptest.NewRequest("POST", "/login", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.Login(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, "Please provide your 2FA code", response["message"])
	assert.True(t, response["requires_2fa"].(bool))
}

// TestLogin_InvalidJSON tests login with invalid JSON
func TestLogin_InvalidJSON(t *testing.T) {
	db := setupTestDB(t)
	
	var mailerInterface *mailer.Mailer
	handler := auth.NewAuthHandler(db, mailerInterface)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	c.Request = httptest.NewRequest("POST", "/login", bytes.NewBufferString("{invalid json"))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.Login(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestChangePassword_Success tests successful password change
func TestChangePassword_Success(t *testing.T) {
	db := setupTestDB(t)
	
	var mailerInterface *mailer.Mailer
	handler := auth.NewAuthHandler(db, mailerInterface)

	user := createTestUser(t, db, "test@example.com", "oldpassword", "user", true, false)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	
	// Set user context (simulating authenticated request)
	c.Set("user_id", user.ID)
	c.Set("user_email", user.Email)

	changeReq := map[string]string{
		"current_password": "oldpassword",
		"new_password":     "newpassword123",
	}
	body, _ := json.Marshal(changeReq)
	c.Request = httptest.NewRequest("POST", "/change-password", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.ChangePassword(c)

	assert.Equal(t, http.StatusOK, w.Code)
	
	// Verify password was actually changed
	var updatedUser models.User
	db.First(&updatedUser, user.ID)
	err := bcrypt.CompareHashAndPassword([]byte(updatedUser.PasswordHash), []byte("newpassword123"))
	assert.NoError(t, err)
}

// TestChangePassword_InvalidCurrentPassword tests password change with wrong current password
func TestChangePassword_InvalidCurrentPassword(t *testing.T) {
	db := setupTestDB(t)
	
	var mailerInterface *mailer.Mailer
	handler := auth.NewAuthHandler(db, mailerInterface)

	user := createTestUser(t, db, "test@example.com", "correctpassword", "user", true, false)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	
	c.Set("user_id", user.ID)
	c.Set("user_email", user.Email)

	changeReq := map[string]string{
		"current_password": "wrongpassword",
		"new_password":     "newpassword123",
	}
	body, _ := json.Marshal(changeReq)
	c.Request = httptest.NewRequest("POST", "/change-password", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.ChangePassword(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestChangePassword_Unauthorized tests password change without authentication
func TestChangePassword_Unauthorized(t *testing.T) {
	db := setupTestDB(t)
	
	var mailerInterface *mailer.Mailer
	handler := auth.NewAuthHandler(db, mailerInterface)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	
	// No user context set

	changeReq := map[string]string{
		"current_password": "password",
		"new_password":     "newpassword123",
	}
	body, _ := json.Marshal(changeReq)
	c.Request = httptest.NewRequest("POST", "/change-password", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.ChangePassword(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestSetPasswordWithToken_Success tests successful password setup with valid token
func TestSetPasswordWithToken_Success(t *testing.T) {
	db := setupTestDB(t)
	
	var mailerInterface *mailer.Mailer
	handler := auth.NewAuthHandler(db, mailerInterface)

	// Create user with invite token
	user := models.User{
		Email:              "newuser@example.com",
		Name:               "New User",
		Role:               "user",
		Active:             false,
		PasswordResetToken: "valid-token-123",
		PasswordResetExpiry: time.Now().Add(24 * time.Hour),
	}
	db.Create(&user)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	setupReq := map[string]string{
		"token":        "valid-token-123",
		"new_password": "newpassword123",
	}
	body, _ := json.Marshal(setupReq)
	c.Request = httptest.NewRequest("POST", "/set-password", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.SetPasswordWithToken(c)

	assert.Equal(t, http.StatusOK, w.Code)
	
	// Verify user is now active and has password
	var updatedUser models.User
	db.First(&updatedUser, user.ID)
	assert.True(t, updatedUser.Active)
	assert.NotEmpty(t, updatedUser.PasswordHash)
	assert.Empty(t, updatedUser.PasswordResetToken)
}

// TestSetPasswordWithToken_InvalidToken tests password setup with invalid token
func TestSetPasswordWithToken_InvalidToken(t *testing.T) {
	db := setupTestDB(t)
	
	var mailerInterface *mailer.Mailer
	handler := auth.NewAuthHandler(db, mailerInterface)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	setupReq := map[string]string{
		"token":        "invalid-token",
		"new_password": "newpassword123",
	}
	body, _ := json.Marshal(setupReq)
	c.Request = httptest.NewRequest("POST", "/set-password", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.SetPasswordWithToken(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestSetPasswordWithToken_ExpiredToken tests password setup with expired token
func TestSetPasswordWithToken_ExpiredToken(t *testing.T) {
	db := setupTestDB(t)

	var mailerInterface *mailer.Mailer
	handler := auth.NewAuthHandler(db, mailerInterface)

	// Create user with expired token
	user := models.User{
		Email:              "newuser@example.com",
		Name:               "New User",
		Role:               "user",
		Active:             false,
		PasswordResetToken: "expired-token-123",
		PasswordResetExpiry: time.Now().Add(-24 * time.Hour), // Expired
	}
	db.Create(&user)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	setupReq := map[string]string{
		"token":        "expired-token-123",
		"new_password": "newpassword123",
	}
	body, _ := json.Marshal(setupReq)
	c.Request = httptest.NewRequest("POST", "/set-password", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.SetPasswordWithToken(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestVerifyOTPLogin_Success tests successful 2FA login with OTP code
func TestVerifyOTPLogin_Success(t *testing.T) {
	db := setupTestDB(t)

	var mailerInterface *mailer.Mailer
	handler := auth.NewAuthHandler(db, mailerInterface)

	user := createTestUser(t, db, "test@example.com", "password123", "user", true, true)

	// Setup 2FA
	otpConfig, _ := auth.SetupTwoFA(&user)
	db.Save(&user)

	// Generate valid OTP code
	now := time.Now()
	counter := now.Unix() / 30
	code := generateTOTPCodeForTest(otpConfig.Secret, counter)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	loginReq := map[string]string{
		"email":    "test@example.com",
		"otp_code": code,
	}
	body, _ := json.Marshal(loginReq)
	c.Request = httptest.NewRequest("POST", "/verify-otp", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.VerifyOTPLogin(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.NotEmpty(t, response["token"])
}

// TestVerifyOTPLogin_BackupCode tests 2FA login with backup code
func TestVerifyOTPLogin_BackupCode(t *testing.T) {
	db := setupTestDB(t)

	var mailerInterface *mailer.Mailer
	handler := auth.NewAuthHandler(db, mailerInterface)

	user := createTestUser(t, db, "test@example.com", "password123", "user", true, true)

	// Setup 2FA
	otpConfig, _ := auth.SetupTwoFA(&user)
	db.Save(&user)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	loginReq := map[string]string{
		"email":       "test@example.com",
		"backup_code": otpConfig.BackupCodes[0],
	}
	body, _ := json.Marshal(loginReq)
	c.Request = httptest.NewRequest("POST", "/verify-otp", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.VerifyOTPLogin(c)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestVerifyOTPLogin_InvalidCode tests 2FA login with invalid OTP
func TestVerifyOTPLogin_InvalidCode(t *testing.T) {
	db := setupTestDB(t)

	var mailerInterface *mailer.Mailer
	handler := auth.NewAuthHandler(db, mailerInterface)

	user := createTestUser(t, db, "test@example.com", "password123", "user", true, true)

	// Setup 2FA
	auth.SetupTwoFA(&user)
	db.Save(&user)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	loginReq := map[string]string{
		"email":    "test@example.com",
		"otp_code": "000000",
	}
	body, _ := json.Marshal(loginReq)
	c.Request = httptest.NewRequest("POST", "/verify-otp", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.VerifyOTPLogin(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestVerifyOTPLogin_NoCode tests 2FA login without providing any code
func TestVerifyOTPLogin_NoCode(t *testing.T) {
	db := setupTestDB(t)

	var mailerInterface *mailer.Mailer
	handler := auth.NewAuthHandler(db, mailerInterface)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	loginReq := map[string]string{
		"email": "test@example.com",
	}
	body, _ := json.Marshal(loginReq)
	c.Request = httptest.NewRequest("POST", "/verify-otp", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.VerifyOTPLogin(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestVerifyOTPLogin_InvalidOTPLength tests 2FA login with wrong OTP length
func TestVerifyOTPLogin_InvalidOTPLength(t *testing.T) {
	db := setupTestDB(t)

	var mailerInterface *mailer.Mailer
	handler := auth.NewAuthHandler(db, mailerInterface)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	loginReq := map[string]string{
		"email":    "test@example.com",
		"otp_code": "12345", // Only 5 digits
	}
	body, _ := json.Marshal(loginReq)
	c.Request = httptest.NewRequest("POST", "/verify-otp", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.VerifyOTPLogin(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestVerifyOTPLogin_UserNotFound tests 2FA login with non-existent user
func TestVerifyOTPLogin_UserNotFound(t *testing.T) {
	db := setupTestDB(t)

	var mailerInterface *mailer.Mailer
	handler := auth.NewAuthHandler(db, mailerInterface)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	loginReq := map[string]string{
		"email":    "nonexistent@example.com",
		"otp_code": "123456",
	}
	body, _ := json.Marshal(loginReq)
	c.Request = httptest.NewRequest("POST", "/verify-otp", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.VerifyOTPLogin(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestAdminCreateUser_Success tests successful user creation by admin
func TestAdminCreateUser_Success(t *testing.T) {
	db := setupTestDB(t)

	mockMail := newMockMailer()
	var mailerInterface *mailer.Mailer
	handler := auth.NewAuthHandler(db, mailerInterface)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	// Set admin context
	c.Set("user_id", uint(1))
	c.Set("user_email", "admin@example.com")

	createReq := map[string]string{
		"email": "newuser@example.com",
		"name":  "New User",
		"role":  "user",
	}
	body, _ := json.Marshal(createReq)
	c.Request = httptest.NewRequest("POST", "/admin/create-user", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.AdminCreateUser(c)

	assert.Equal(t, http.StatusCreated, w.Code)

	// Verify user was created
	var user models.User
	err := db.Where("email = ?", "newuser@example.com").First(&user).Error
	assert.NoError(t, err)
	assert.Equal(t, "New User", user.Name)
	assert.False(t, user.Active) // Should be inactive until password is set
	_ = mockMail
}

// TestAdminCreateUser_EmailAlreadyExists tests user creation with existing email
func TestAdminCreateUser_EmailAlreadyExists(t *testing.T) {
	db := setupTestDB(t)

	var mailerInterface *mailer.Mailer
	handler := auth.NewAuthHandler(db, mailerInterface)

	// Create existing user
	createTestUser(t, db, "existing@example.com", "password123", "user", true, false)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	c.Set("user_id", uint(1))
	c.Set("user_email", "admin@example.com")

	createReq := map[string]string{
		"email": "existing@example.com",
		"name":  "Duplicate User",
		"role":  "user",
	}
	body, _ := json.Marshal(createReq)
	c.Request = httptest.NewRequest("POST", "/admin/create-user", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.AdminCreateUser(c)

	assert.Equal(t, http.StatusConflict, w.Code)
}

// TestAdminCreateUser_InvalidRole tests user creation with invalid role
func TestAdminCreateUser_InvalidRole(t *testing.T) {
	db := setupTestDB(t)

	var mailerInterface *mailer.Mailer
	handler := auth.NewAuthHandler(db, mailerInterface)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	c.Set("user_id", uint(1))
	c.Set("user_email", "admin@example.com")

	createReq := map[string]string{
		"email": "newuser@example.com",
		"name":  "New User",
		"role":  "superadmin", // Invalid role
	}
	body, _ := json.Marshal(createReq)
	c.Request = httptest.NewRequest("POST", "/admin/create-user", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.AdminCreateUser(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestAdminCreateUser_InvalidJSON tests user creation with invalid JSON
func TestAdminCreateUser_InvalidJSON(t *testing.T) {
	db := setupTestDB(t)

	var mailerInterface *mailer.Mailer
	handler := auth.NewAuthHandler(db, mailerInterface)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	c.Set("user_id", uint(1))
	c.Set("user_email", "admin@example.com")

	c.Request = httptest.NewRequest("POST", "/admin/create-user", bytes.NewBufferString("{invalid"))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.AdminCreateUser(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestInitiateTwoFASetup_Success tests successful 2FA setup initiation
func TestInitiateTwoFASetup_Success(t *testing.T) {
	db := setupTestDB(t)

	var mailerInterface *mailer.Mailer
	handler := auth.NewAuthHandler(db, mailerInterface)

	user := createTestUser(t, db, "test@example.com", "password123", "user", true, false)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	c.Set("user_id", user.ID)

	c.Request = httptest.NewRequest("POST", "/initiate-2fa", nil)

	handler.InitiateTwoFASetup(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.NotEmpty(t, response["qr_code_url"])
	assert.NotEmpty(t, response["secret"])
	assert.NotEmpty(t, response["backup_codes"])
}

// TestInitiateTwoFASetup_Unauthorized tests 2FA setup without authentication
func TestInitiateTwoFASetup_Unauthorized(t *testing.T) {
	db := setupTestDB(t)

	var mailerInterface *mailer.Mailer
	handler := auth.NewAuthHandler(db, mailerInterface)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	c.Request = httptest.NewRequest("POST", "/initiate-2fa", nil)

	handler.InitiateTwoFASetup(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestCompleteTwoFASetup_Success tests successful 2FA setup completion
func TestCompleteTwoFASetup_Success(t *testing.T) {
	db := setupTestDB(t)

	var mailerInterface *mailer.Mailer
	handler := auth.NewAuthHandler(db, mailerInterface)

	user := createTestUser(t, db, "test@example.com", "password123", "user", true, false)

	// Generate secret
	secret, _ := auth.GenerateOTPSecret()

	// Generate valid OTP code
	now := time.Now()
	counter := now.Unix() / 30
	code := generateTOTPCodeForTest(secret, counter)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	c.Set("user_id", user.ID)

	completeReq := map[string]string{
		"secret":   secret,
		"otp_code": code,
	}
	body, _ := json.Marshal(completeReq)
	c.Request = httptest.NewRequest("POST", "/complete-2fa", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.CompleteTwoFASetup(c)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify user now has 2FA enabled
	var updatedUser models.User
	db.First(&updatedUser, user.ID)
	assert.True(t, updatedUser.TwoFAEnabled)
	assert.NotEmpty(t, updatedUser.OTPSecret)
}

// TestCompleteTwoFASetup_InvalidOTP tests 2FA setup with invalid OTP
func TestCompleteTwoFASetup_InvalidOTP(t *testing.T) {
	db := setupTestDB(t)

	var mailerInterface *mailer.Mailer
	handler := auth.NewAuthHandler(db, mailerInterface)

	user := createTestUser(t, db, "test@example.com", "password123", "user", true, false)

	secret, _ := auth.GenerateOTPSecret()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	c.Set("user_id", user.ID)

	completeReq := map[string]string{
		"secret":   secret,
		"otp_code": "000000", // Invalid code
	}
	body, _ := json.Marshal(completeReq)
	c.Request = httptest.NewRequest("POST", "/complete-2fa", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.CompleteTwoFASetup(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestDisableTwoFA_Success tests successful 2FA disabling
func TestDisableTwoFA_Success(t *testing.T) {
	db := setupTestDB(t)

	var mailerInterface *mailer.Mailer
	handler := auth.NewAuthHandler(db, mailerInterface)

	user := createTestUser(t, db, "test@example.com", "password123", "user", true, true)

	// Setup 2FA
	auth.SetupTwoFA(&user)
	db.Save(&user)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	c.Set("user_id", user.ID)

	disableReq := map[string]string{
		"password": "password123",
	}
	body, _ := json.Marshal(disableReq)
	c.Request = httptest.NewRequest("POST", "/disable-2fa", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.DisableTwoFA(c)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify 2FA is disabled
	var updatedUser models.User
	db.First(&updatedUser, user.ID)
	assert.False(t, updatedUser.TwoFAEnabled)
	assert.Empty(t, updatedUser.OTPSecret)
}

// TestDisableTwoFA_InvalidPassword tests 2FA disabling with wrong password
func TestDisableTwoFA_InvalidPassword(t *testing.T) {
	db := setupTestDB(t)

	var mailerInterface *mailer.Mailer
	handler := auth.NewAuthHandler(db, mailerInterface)

	user := createTestUser(t, db, "test@example.com", "password123", "user", true, true)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	c.Set("user_id", user.ID)

	disableReq := map[string]string{
		"password": "wrongpassword",
	}
	body, _ := json.Marshal(disableReq)
	c.Request = httptest.NewRequest("POST", "/disable-2fa", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.DisableTwoFA(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestForgotPassword_Success tests password reset request
func TestForgotPassword_Success(t *testing.T) {
	db := setupTestDB(t)

	mockMail := newMockMailer()
	// Create a minimal mailer with mock
	mailerObj := &mailer.Mailer{}
	handler := auth.NewAuthHandler(db, mailerObj)

	createTestUser(t, db, "test@example.com", "password123", "user", true, false)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	forgotReq := map[string]string{
		"email": "test@example.com",
	}
	body, _ := json.Marshal(forgotReq)
	c.Request = httptest.NewRequest("POST", "/forgot-password", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.ForgotPassword(c)

	// Should always return 200 for security (don't reveal if email exists)
	assert.Equal(t, http.StatusOK, w.Code)
	_ = mockMail
}

// TestForgotPassword_NonExistentUser tests password reset for non-existent user
func TestForgotPassword_NonExistentUser(t *testing.T) {
	db := setupTestDB(t)

	var mailerInterface *mailer.Mailer
	handler := auth.NewAuthHandler(db, mailerInterface)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	forgotReq := map[string]string{
		"email": "nonexistent@example.com",
	}
	body, _ := json.Marshal(forgotReq)
	c.Request = httptest.NewRequest("POST", "/forgot-password", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.ForgotPassword(c)

	// Should still return 200 for security
	assert.Equal(t, http.StatusOK, w.Code)
}

// TestForgotPassword_InvalidEmail tests password reset with invalid email format
func TestForgotPassword_InvalidEmail(t *testing.T) {
	db := setupTestDB(t)

	var mailerInterface *mailer.Mailer
	handler := auth.NewAuthHandler(db, mailerInterface)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	forgotReq := map[string]string{
		"email": "not-an-email",
	}
	body, _ := json.Marshal(forgotReq)
	c.Request = httptest.NewRequest("POST", "/forgot-password", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.ForgotPassword(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestResetPassword_Success tests successful password reset
func TestResetPassword_Success(t *testing.T) {
	db := setupTestDB(t)

	var mailerInterface *mailer.Mailer
	handler := auth.NewAuthHandler(db, mailerInterface)

	// Create user with reset token (token needs to be bcrypt hashed)
	user := createTestUser(t, db, "test@example.com", "oldpassword", "user", true, false)
	plainToken := "valid-reset-token-123"
	hashedToken, _ := bcrypt.GenerateFromPassword([]byte(plainToken), bcrypt.DefaultCost)
	tokenExpiry := time.Now().Add(1 * time.Hour)
	user.PasswordResetToken = string(hashedToken)
	user.PasswordResetExpiry = tokenExpiry
	db.Save(&user)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	resetReq := map[string]string{
		"token":        plainToken,
		"new_password": "NewSecurePassword123!",
	}
	body, _ := json.Marshal(resetReq)
	c.Request = httptest.NewRequest("POST", "/reset-password", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.ResetPassword(c)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify password was changed and token was cleared
	var updatedUser models.User
	db.First(&updatedUser, user.ID)
	assert.Empty(t, updatedUser.PasswordResetToken)

	// Verify new password works
	err := bcrypt.CompareHashAndPassword([]byte(updatedUser.PasswordHash), []byte("NewSecurePassword123!"))
	assert.NoError(t, err)
}

// TestResetPassword_InvalidToken tests password reset with invalid token
func TestResetPassword_InvalidToken(t *testing.T) {
	db := setupTestDB(t)

	var mailerInterface *mailer.Mailer
	handler := auth.NewAuthHandler(db, mailerInterface)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	resetReq := map[string]string{
		"token":        "invalid-token",
		"new_password": "NewPassword123!",
	}
	body, _ := json.Marshal(resetReq)
	c.Request = httptest.NewRequest("POST", "/reset-password", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.ResetPassword(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestResetPassword_ExpiredToken tests password reset with expired token
func TestResetPassword_ExpiredToken(t *testing.T) {
	db := setupTestDB(t)

	var mailerInterface *mailer.Mailer
	handler := auth.NewAuthHandler(db, mailerInterface)

	// Create user with expired reset token
	user := createTestUser(t, db, "test@example.com", "oldpassword", "user", true, false)
	plainToken := "expired-token-123"
	hashedToken, _ := bcrypt.GenerateFromPassword([]byte(plainToken), bcrypt.DefaultCost)
	tokenExpiry := time.Now().Add(-1 * time.Hour) // Expired 1 hour ago
	user.PasswordResetToken = string(hashedToken)
	user.PasswordResetExpiry = tokenExpiry
	db.Save(&user)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	resetReq := map[string]string{
		"token":        plainToken,
		"new_password": "NewPassword123!",
	}
	body, _ := json.Marshal(resetReq)
	c.Request = httptest.NewRequest("POST", "/reset-password", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.ResetPassword(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestResetPassword_InvalidJSON tests password reset with malformed JSON
func TestResetPassword_InvalidJSON(t *testing.T) {
	db := setupTestDB(t)

	var mailerInterface *mailer.Mailer
	handler := auth.NewAuthHandler(db, mailerInterface)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	c.Request = httptest.NewRequest("POST", "/reset-password", bytes.NewBufferString("invalid-json"))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.ResetPassword(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestResetPassword_MissingPassword tests password reset without password
func TestResetPassword_MissingPassword(t *testing.T) {
	db := setupTestDB(t)

	var mailerInterface *mailer.Mailer
	handler := auth.NewAuthHandler(db, mailerInterface)

	user := createTestUser(t, db, "test@example.com", "oldpassword", "user", true, false)
	plainToken := "valid-token-123"
	hashedToken, _ := bcrypt.GenerateFromPassword([]byte(plainToken), bcrypt.DefaultCost)
	tokenExpiry := time.Now().Add(1 * time.Hour)
	user.PasswordResetToken = string(hashedToken)
	user.PasswordResetExpiry = tokenExpiry
	db.Save(&user)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	resetReq := map[string]string{
		"token":        plainToken,
		"new_password": "", // Empty password
	}
	body, _ := json.Marshal(resetReq)
	c.Request = httptest.NewRequest("POST", "/reset-password", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.ResetPassword(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// Helper function to generate TOTP code for tests
func generateTOTPCodeForTest(secret string, counter int64) string {
	return generateTOTPCode(secret, counter)
}
