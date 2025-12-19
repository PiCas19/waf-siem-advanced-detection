package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/api"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestNewGetRulesHandler_Success tests successful rules retrieval
func TestNewGetRulesHandler_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockRuleRepo := new(MockRuleRepository)
	ruleService := service.NewRuleService(mockRuleRepo)

	expectedRules := []models.Rule{
		{
			ID:       1,
			Name:     "Test Rule 1",
			Pattern:  "test.*pattern",
			Type:     "custom",
			Severity: "high",
			Enabled:  true,
		},
		{
			ID:       2,
			Name:     "Test Rule 2",
			Pattern:  "another.*pattern",
			Type:     "custom",
			Severity: "medium",
			Enabled:  true,
		},
	}

	mockRuleRepo.On("FindPaginated", mock.Anything, 0, 20).
		Return(expectedRules, int64(2), nil).Once()

	handler := api.NewGetRulesHandler(ruleService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/api/rules", nil)

	handler(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotNil(t, resp["default_rules"])
	assert.NotNil(t, resp["custom_rules"])
	assert.Equal(t, float64(2), resp["total_custom_rules"])

	mockRuleRepo.AssertExpectations(t)
}

// TestNewGetRulesHandler_InvalidPagination tests with invalid pagination parameters
func TestNewGetRulesHandler_InvalidPagination(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockRuleRepo := new(MockRuleRepository)
	ruleService := service.NewRuleService(mockRuleRepo)

	handler := api.NewGetRulesHandler(ruleService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/api/rules?limit=invalid", nil)

	handler(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Contains(t, resp["code"], "INVALID_REQUEST")

	mockRuleRepo.AssertNotCalled(t, "FindPaginated")
}

// TestNewGetRulesHandler_ServiceError tests service error handling
func TestNewGetRulesHandler_ServiceError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockRuleRepo := new(MockRuleRepository)
	ruleService := service.NewRuleService(mockRuleRepo)

	mockRuleRepo.On("FindPaginated", mock.Anything, 0, 20).
		Return([]models.Rule{}, int64(0), errors.New("database error")).Once()

	handler := api.NewGetRulesHandler(ruleService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/api/rules", nil)

	handler(c)

	// Service error should still return 200 with empty results
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, float64(0), resp["total_custom_rules"])

	mockRuleRepo.AssertExpectations(t)
}

// TestNewGetCustomRulesHandler_Success tests successful custom rules retrieval
func TestNewGetCustomRulesHandler_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockRuleRepo := new(MockRuleRepository)
	ruleService := service.NewRuleService(mockRuleRepo)

	expectedRules := []models.Rule{
		{
			ID:       1,
			Name:     "Custom Rule 1",
			Pattern:  "test.*pattern",
			Enabled:  true,
		},
	}

	mockRuleRepo.On("FindEnabled", mock.Anything).
		Return(expectedRules, nil).Once()

	handler := api.NewGetCustomRulesHandler(ruleService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/api/waf/custom-rules", nil)

	handler(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, float64(1), resp["count"])

	mockRuleRepo.AssertExpectations(t)
}

// TestNewGetCustomRulesHandler_ServiceError tests service error handling
func TestNewGetCustomRulesHandler_ServiceError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockRuleRepo := new(MockRuleRepository)
	ruleService := service.NewRuleService(mockRuleRepo)

	mockRuleRepo.On("FindEnabled", mock.Anything).
		Return([]models.Rule{}, errors.New("database error")).Once()

	handler := api.NewGetCustomRulesHandler(ruleService)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/api/waf/custom-rules", nil)

	handler(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "DATABASE_ERROR", resp["code"])

	mockRuleRepo.AssertExpectations(t)
}

// TestNewCreateRuleHandler_Success tests successful rule creation
func TestNewCreateRuleHandler_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockRuleRepo := new(MockRuleRepository)
	ruleService := service.NewRuleService(mockRuleRepo)
	db := setupTestDB()

	// Create a test user for audit logging
	testUser := models.User{Email: "test@example.com"}
	db.Create(&testUser)

	mockRuleRepo.On("Create", mock.Anything, mock.MatchedBy(func(rule *models.Rule) bool {
		return rule.Name == "Test XSS Rule" &&
			rule.Pattern == "<script>.*</script>" &&
			rule.Enabled == true &&
			rule.Severity == "high" &&
			rule.CreatedBy == testUser.ID
	})).Return(nil).Once()

	handler := api.NewCreateRuleHandler(ruleService, db)

	reqBody := map[string]interface{}{
		"name":        "Test XSS Rule",
		"pattern":     "<script>.*</script>",
		"description": "Blocks XSS attempts",
		"type":        "xss",
		"severity":    "high",
		"action":      "block",
	}
	jsonData, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", "/api/rules", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Set("user_id", testUser.ID)
	c.Set("user_email", testUser.Email)
	c.Set("client_ip", "127.0.0.1")

	handler(c)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "Rule created successfully", resp["message"])

	mockRuleRepo.AssertExpectations(t)
}

// TestNewCreateRuleHandler_LogAction tests rule creation with log action
func TestNewCreateRuleHandler_LogAction(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockRuleRepo := new(MockRuleRepository)
	ruleService := service.NewRuleService(mockRuleRepo)
	db := setupTestDB()

	testUser := models.User{Email: "test@example.com"}
	db.Create(&testUser)

	mockRuleRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.Rule")).
		Run(func(args mock.Arguments) {
			rule := args.Get(1).(*models.Rule)
			// Verify when action is "log", all block actions should be disabled
			assert.Equal(t, "Log Only Rule", rule.Name)
			assert.Equal(t, "log", rule.Action)
			assert.False(t, rule.BlockEnabled)
			assert.False(t, rule.DropEnabled)
			assert.False(t, rule.RedirectEnabled)
			assert.False(t, rule.ChallengeEnabled)
		}).Return(nil).Once()

	handler := api.NewCreateRuleHandler(ruleService, db)

	reqBody := map[string]interface{}{
		"name":    "Log Only Rule",
		"pattern": "test.*",
		"type":    "custom",
		"action":  "log",
	}
	jsonData, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", "/api/rules", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Set("user_id", testUser.ID)
	c.Set("user_email", testUser.Email)
	c.Set("client_ip", "127.0.0.1")

	handler(c)

	assert.Equal(t, http.StatusCreated, w.Code)
	mockRuleRepo.AssertExpectations(t)
}

// TestNewCreateRuleHandler_DefaultSeverity tests rule creation with default severity
func TestNewCreateRuleHandler_DefaultSeverity(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockRuleRepo := new(MockRuleRepository)
	ruleService := service.NewRuleService(mockRuleRepo)
	db := setupTestDB()

	testUser := models.User{Email: "test@example.com"}
	db.Create(&testUser)

	mockRuleRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.Rule")).
		Run(func(args mock.Arguments) {
			rule := args.Get(1).(*models.Rule)
			// Should default to "medium" severity
			assert.Equal(t, "medium", rule.Severity)
			assert.Equal(t, "Test Rule", rule.Name)
		}).Return(nil).Once()

	handler := api.NewCreateRuleHandler(ruleService, db)

	reqBody := map[string]interface{}{
		"name":    "Test Rule",
		"pattern": "test.*",
		"type":    "custom",
	}
	jsonData, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", "/api/rules", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Set("user_id", testUser.ID)
	c.Set("user_email", testUser.Email)
	c.Set("client_ip", "127.0.0.1")

	handler(c)

	assert.Equal(t, http.StatusCreated, w.Code)
	mockRuleRepo.AssertExpectations(t)
}

// TestNewCreateRuleHandler_InvalidJSON tests with malformed JSON
func TestNewCreateRuleHandler_InvalidJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockRuleRepo := new(MockRuleRepository)
	ruleService := service.NewRuleService(mockRuleRepo)
	db := setupTestDB()

	testUser := models.User{Email: "test@example.com"}
	db.Create(&testUser)

	handler := api.NewCreateRuleHandler(ruleService, db)

	req, _ := http.NewRequest("POST", "/api/rules", bytes.NewBufferString("{invalid json"))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Set("user_id", testUser.ID)
	c.Set("user_email", testUser.Email)
	c.Set("client_ip", "127.0.0.1")

	handler(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Contains(t, resp["code"], "INVALID_JSON")

	mockRuleRepo.AssertNotCalled(t, "Create")
}

// TestNewCreateRuleHandler_MissingName tests with missing name field
func TestNewCreateRuleHandler_MissingName(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockRuleRepo := new(MockRuleRepository)
	ruleService := service.NewRuleService(mockRuleRepo)
	db := setupTestDB()

	testUser := models.User{Email: "test@example.com"}
	db.Create(&testUser)

	handler := api.NewCreateRuleHandler(ruleService, db)

	reqBody := map[string]interface{}{
		"pattern": "test.*",
	}
	jsonData, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", "/api/rules", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Set("user_id", testUser.ID)
	c.Set("user_email", testUser.Email)
	c.Set("client_ip", "127.0.0.1")

	handler(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "MISSING_FIELD", resp["code"])

	mockRuleRepo.AssertNotCalled(t, "Create")
}

// TestNewCreateRuleHandler_MissingPattern tests with missing pattern field
func TestNewCreateRuleHandler_MissingPattern(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockRuleRepo := new(MockRuleRepository)
	ruleService := service.NewRuleService(mockRuleRepo)
	db := setupTestDB()

	testUser := models.User{Email: "test@example.com"}
	db.Create(&testUser)

	handler := api.NewCreateRuleHandler(ruleService, db)

	reqBody := map[string]interface{}{
		"name": "Test Rule",
	}
	jsonData, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", "/api/rules", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Set("user_id", testUser.ID)
	c.Set("user_email", testUser.Email)
	c.Set("client_ip", "127.0.0.1")

	handler(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "MISSING_FIELD", resp["code"])

	mockRuleRepo.AssertNotCalled(t, "Create")
}

// TestNewCreateRuleHandler_InvalidRuleName tests with invalid rule name
func TestNewCreateRuleHandler_InvalidRuleName(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockRuleRepo := new(MockRuleRepository)
	ruleService := service.NewRuleService(mockRuleRepo)
	db := setupTestDB()

	testUser := models.User{Email: "test@example.com"}
	db.Create(&testUser)

	handler := api.NewCreateRuleHandler(ruleService, db)

	// Create a name that exceeds 255 characters
	longName := ""
	for i := 0; i < 260; i++ {
		longName += "a"
	}

	reqBody := map[string]interface{}{
		"name":    longName, // Name too long (>255 chars)
		"pattern": "test.*",
	}
	jsonData, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", "/api/rules", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Set("user_id", testUser.ID)
	c.Set("user_email", testUser.Email)
	c.Set("client_ip", "127.0.0.1")

	handler(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Contains(t, resp["code"], "INVALID_REQUEST")

	mockRuleRepo.AssertNotCalled(t, "Create")
}

// TestNewCreateRuleHandler_InvalidPattern tests with invalid pattern
func TestNewCreateRuleHandler_InvalidPattern(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockRuleRepo := new(MockRuleRepository)
	ruleService := service.NewRuleService(mockRuleRepo)
	db := setupTestDB()

	testUser := models.User{Email: "test@example.com"}
	db.Create(&testUser)

	handler := api.NewCreateRuleHandler(ruleService, db)

	reqBody := map[string]interface{}{
		"name":    "Test Rule",
		"pattern": "(unclosed", // Invalid regex
	}
	jsonData, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", "/api/rules", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Set("user_id", testUser.ID)
	c.Set("user_email", testUser.Email)
	c.Set("client_ip", "127.0.0.1")

	handler(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Contains(t, resp["code"], "INVALID_REQUEST")

	mockRuleRepo.AssertNotCalled(t, "Create")
}

// TestNewCreateRuleHandler_InvalidDescription tests with invalid description
func TestNewCreateRuleHandler_InvalidDescription(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockRuleRepo := new(MockRuleRepository)
	ruleService := service.NewRuleService(mockRuleRepo)
	db := setupTestDB()

	testUser := models.User{Email: "test@example.com"}
	db.Create(&testUser)

	handler := api.NewCreateRuleHandler(ruleService, db)

	// Create a description longer than the limit
	longDesc := ""
	for i := 0; i < 1001; i++ {
		longDesc += "a"
	}

	reqBody := map[string]interface{}{
		"name":        "Test Rule",
		"pattern":     "test.*",
		"description": longDesc,
	}
	jsonData, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", "/api/rules", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Set("user_id", testUser.ID)
	c.Set("user_email", testUser.Email)
	c.Set("client_ip", "127.0.0.1")

	handler(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Contains(t, resp["code"], "INVALID_REQUEST")

	mockRuleRepo.AssertNotCalled(t, "Create")
}

// TestNewCreateRuleHandler_DatabaseError tests database error handling
func TestNewCreateRuleHandler_DatabaseError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockRuleRepo := new(MockRuleRepository)
	ruleService := service.NewRuleService(mockRuleRepo)
	db := setupTestDB()

	testUser := models.User{Email: "test@example.com"}
	db.Create(&testUser)

	mockRuleRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.Rule")).
		Return(errors.New("database connection error")).Once()

	handler := api.NewCreateRuleHandler(ruleService, db)

	reqBody := map[string]interface{}{
		"name":    "Test Rule",
		"pattern": "test.*",
		"type":    "custom",
	}
	jsonData, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", "/api/rules", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Set("user_id", testUser.ID)
	c.Set("user_email", testUser.Email)
	c.Set("client_ip", "127.0.0.1")

	handler(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "DATABASE_ERROR", resp["code"])

	mockRuleRepo.AssertExpectations(t)
}

// TestNewUpdateRuleHandler_Success tests successful rule update
func TestNewUpdateRuleHandler_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockRuleRepo := new(MockRuleRepository)
	ruleService := service.NewRuleService(mockRuleRepo)
	db := setupTestDB()

	// Migrate Rule table for updates
	db.AutoMigrate(&models.Rule{})

	testUser := models.User{Email: "test@example.com"}
	db.Create(&testUser)

	// Create the rule in the real database first
	existingRule := &models.Rule{
		Name:          "Old Name",
		Pattern:       "old.*pattern",
		Enabled:       true,
		IsManualBlock: false,
	}
	db.Create(existingRule)

	// Mock FindByID to return the existing rule
	mockRuleRepo.On("FindByID", mock.Anything, existingRule.ID).
		Return(existingRule, nil).Once()

	// After update, mock FindByID to return the updated rule
	mockRuleRepo.On("FindByID", mock.Anything, existingRule.ID).
		Return(&models.Rule{
			ID:      existingRule.ID,
			Name:    "New Name",
			Pattern: "new.*pattern",
			Enabled: false,
		}, nil).Once()

	handler := api.NewUpdateRuleHandler(ruleService, db)

	reqBody := map[string]interface{}{
		"name":    "New Name",
		"pattern": "new.*pattern",
		"enabled": false,
	}
	jsonData, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("PUT", fmt.Sprintf("/api/rules/%d", existingRule.ID), bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = gin.Params{{Key: "id", Value: fmt.Sprintf("%d", existingRule.ID)}}
	c.Set("user_id", testUser.ID)
	c.Set("user_email", testUser.Email)
	c.Set("client_ip", "127.0.0.1")

	handler(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "Rule updated successfully", resp["message"])

	mockRuleRepo.AssertExpectations(t)
}

// TestNewUpdateRuleHandler_LogAction tests update with log action
func TestNewUpdateRuleHandler_LogAction(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockRuleRepo := new(MockRuleRepository)
	ruleService := service.NewRuleService(mockRuleRepo)
	db := setupTestDB()

	// Migrate Rule table
	db.AutoMigrate(&models.Rule{})

	testUser := models.User{Email: "test@example.com"}
	db.Create(&testUser)

	existingRule := &models.Rule{
		Name:             "Test Rule",
		Pattern:          "test.*",
		Enabled:          true,
		IsManualBlock:    false,
		BlockEnabled:     true,
		DropEnabled:      true,
		RedirectEnabled:  true,
		ChallengeEnabled: true,
	}
	db.Create(existingRule)

	mockRuleRepo.On("FindByID", mock.Anything, existingRule.ID).
		Return(existingRule, nil).Once()

	mockRuleRepo.On("FindByID", mock.Anything, existingRule.ID).
		Return(&models.Rule{
			ID:      existingRule.ID,
			Name:    "Test Rule",
			Pattern: "test.*",
			Action:  "log",
			Enabled: true,
		}, nil).Once()

	handler := api.NewUpdateRuleHandler(ruleService, db)

	reqBody := map[string]interface{}{
		"action":  "log",
		"enabled": true,
	}
	jsonData, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("PUT", fmt.Sprintf("/api/rules/%d", existingRule.ID), bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = gin.Params{{Key: "id", Value: fmt.Sprintf("%d", existingRule.ID)}}
	c.Set("user_id", testUser.ID)
	c.Set("user_email", testUser.Email)
	c.Set("client_ip", "127.0.0.1")

	handler(c)

	assert.Equal(t, http.StatusOK, w.Code)
	mockRuleRepo.AssertExpectations(t)
}

// TestNewUpdateRuleHandler_InvalidID tests with invalid rule ID
func TestNewUpdateRuleHandler_InvalidID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockRuleRepo := new(MockRuleRepository)
	ruleService := service.NewRuleService(mockRuleRepo)
	db := setupTestDB()

	testUser := models.User{Email: "test@example.com"}
	db.Create(&testUser)

	handler := api.NewUpdateRuleHandler(ruleService, db)

	reqBody := map[string]interface{}{
		"name": "Test",
	}
	jsonData, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("PUT", "/api/rules/invalid", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = gin.Params{{Key: "id", Value: "invalid"}}
	c.Set("user_id", testUser.ID)
	c.Set("user_email", testUser.Email)
	c.Set("client_ip", "127.0.0.1")

	handler(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Contains(t, resp["code"], "INVALID_REQUEST")

	mockRuleRepo.AssertNotCalled(t, "FindByID")
}

// TestNewUpdateRuleHandler_RuleNotFound tests with non-existent rule
func TestNewUpdateRuleHandler_RuleNotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockRuleRepo := new(MockRuleRepository)
	ruleService := service.NewRuleService(mockRuleRepo)
	db := setupTestDB()

	testUser := models.User{Email: "test@example.com"}
	db.Create(&testUser)

	// Return nil,nil so service returns "rule not found"
	mockRuleRepo.On("FindByID", mock.Anything, uint(999)).
		Return((*models.Rule)(nil), nil).Once()

	handler := api.NewUpdateRuleHandler(ruleService, db)

	reqBody := map[string]interface{}{
		"name": "Test",
	}
	jsonData, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("PUT", "/api/rules/999", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = gin.Params{{Key: "id", Value: "999"}}
	c.Set("user_id", testUser.ID)
	c.Set("user_email", testUser.Email)
	c.Set("client_ip", "127.0.0.1")

	handler(c)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "RULE_NOT_FOUND", resp["code"])

	mockRuleRepo.AssertExpectations(t)
}

// TestNewUpdateRuleHandler_ManualBlockForbidden tests updating manual block rule
func TestNewUpdateRuleHandler_ManualBlockForbidden(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockRuleRepo := new(MockRuleRepository)
	ruleService := service.NewRuleService(mockRuleRepo)
	db := setupTestDB()

	testUser := models.User{Email: "test@example.com"}
	db.Create(&testUser)

	manualBlockRule := &models.Rule{
		ID:            1,
		Name:          "Manual Block: Test",
		IsManualBlock: true,
	}

	mockRuleRepo.On("FindByID", mock.Anything, uint(1)).
		Return(manualBlockRule, nil).Once()

	handler := api.NewUpdateRuleHandler(ruleService, db)

	reqBody := map[string]interface{}{
		"name": "New Name",
	}
	jsonData, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("PUT", "/api/rules/1", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = gin.Params{{Key: "id", Value: "1"}}
	c.Set("user_id", testUser.ID)
	c.Set("user_email", testUser.Email)
	c.Set("client_ip", "127.0.0.1")

	handler(c)

	assert.Equal(t, http.StatusForbidden, w.Code)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "CANNOT_EDIT_MANUAL_BLOCK", resp["code"])

	mockRuleRepo.AssertExpectations(t)
}

// TestNewUpdateRuleHandler_InvalidJSON tests with invalid JSON
func TestNewUpdateRuleHandler_InvalidJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockRuleRepo := new(MockRuleRepository)
	ruleService := service.NewRuleService(mockRuleRepo)
	db := setupTestDB()

	testUser := models.User{Email: "test@example.com"}
	db.Create(&testUser)

	existingRule := &models.Rule{
		ID:            1,
		Name:          "Test",
		IsManualBlock: false,
	}

	mockRuleRepo.On("FindByID", mock.Anything, uint(1)).
		Return(existingRule, nil).Once()

	handler := api.NewUpdateRuleHandler(ruleService, db)

	req, _ := http.NewRequest("PUT", "/api/rules/1", bytes.NewBufferString("{invalid json"))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = gin.Params{{Key: "id", Value: "1"}}
	c.Set("user_id", testUser.ID)
	c.Set("user_email", testUser.Email)
	c.Set("client_ip", "127.0.0.1")

	handler(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Contains(t, resp["code"], "INVALID_JSON")

	mockRuleRepo.AssertExpectations(t)
}

// TestNewUpdateRuleHandler_DatabaseError tests database update error
func TestNewUpdateRuleHandler_DatabaseError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockRuleRepo := new(MockRuleRepository)
	ruleService := service.NewRuleService(mockRuleRepo)
	db := setupTestDB()

	// Close the database to force an error
	sqlDB, _ := db.DB()
	sqlDB.Close()

	testUser := models.User{Email: "test@example.com"}

	existingRule := &models.Rule{
		ID:            1,
		Name:          "Test",
		IsManualBlock: false,
	}

	mockRuleRepo.On("FindByID", mock.Anything, uint(1)).
		Return(existingRule, nil).Once()

	handler := api.NewUpdateRuleHandler(ruleService, db)

	reqBody := map[string]interface{}{
		"name": "New Name",
	}
	jsonData, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("PUT", "/api/rules/1", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = gin.Params{{Key: "id", Value: "1"}}
	c.Set("user_id", uint(1))
	c.Set("user_email", testUser.Email)
	c.Set("client_ip", "127.0.0.1")

	handler(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "DATABASE_ERROR", resp["code"])

	mockRuleRepo.AssertExpectations(t)
}

// TestNewDeleteRuleHandler_Success tests successful rule deletion
func TestNewDeleteRuleHandler_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockRuleRepo := new(MockRuleRepository)
	ruleService := service.NewRuleService(mockRuleRepo)
	db := setupTestDB()

	testUser := models.User{Email: "test@example.com"}
	db.Create(&testUser)

	existingRule := &models.Rule{
		ID:            1,
		Name:          "Test Rule",
		IsManualBlock: false,
	}

	mockRuleRepo.On("FindByID", mock.Anything, uint(1)).
		Return(existingRule, nil).Once()

	mockRuleRepo.On("Delete", mock.Anything, uint(1)).
		Return(nil).Once()

	handler := api.NewDeleteRuleHandler(ruleService, db)

	req, _ := http.NewRequest("DELETE", "/api/rules/1", nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = gin.Params{{Key: "id", Value: "1"}}
	c.Set("user_id", testUser.ID)
	c.Set("user_email", testUser.Email)
	c.Set("client_ip", "127.0.0.1")

	handler(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "Rule deleted successfully", resp["message"])
	assert.Equal(t, false, resp["manual_block_deleted"])

	mockRuleRepo.AssertExpectations(t)
}

// TestNewDeleteRuleHandler_ManualBlock tests deleting manual block rule
func TestNewDeleteRuleHandler_ManualBlock(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockRuleRepo := new(MockRuleRepository)
	ruleService := service.NewRuleService(mockRuleRepo)
	db := setupTestDB()

	testUser := models.User{Email: "test@example.com"}
	db.Create(&testUser)

	// Create a manual block log that should be reverted
	log := models.Log{
		ThreatType:  "XSS Attack",
		Description: "XSS Attack",
		Payload:     "<script>alert('xss')</script>",
		Blocked:     true,
		BlockedBy:   "manual",
	}
	db.Create(&log)

	manualBlockRule := &models.Rule{
		ID:            1,
		Name:          "Manual Block: XSS Attack",
		Pattern:       "<script>alert('xss')</script>",
		IsManualBlock: true,
		Severity:      "high",
	}

	mockRuleRepo.On("FindByID", mock.Anything, uint(1)).
		Return(manualBlockRule, nil).Once()

	mockRuleRepo.On("Delete", mock.Anything, uint(1)).
		Return(nil).Once()

	handler := api.NewDeleteRuleHandler(ruleService, db)

	req, _ := http.NewRequest("DELETE", "/api/rules/1", nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = gin.Params{{Key: "id", Value: "1"}}
	c.Set("user_id", testUser.ID)
	c.Set("user_email", testUser.Email)
	c.Set("client_ip", "127.0.0.1")

	handler(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "Rule deleted successfully", resp["message"])
	assert.Equal(t, true, resp["manual_block_deleted"])

	// Verify log was reverted
	var updatedLog models.Log
	db.First(&updatedLog, log.ID)
	assert.False(t, updatedLog.Blocked)
	assert.Empty(t, updatedLog.BlockedBy)

	mockRuleRepo.AssertExpectations(t)
}

// TestNewDeleteRuleHandler_InvalidID tests with invalid rule ID
func TestNewDeleteRuleHandler_InvalidID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockRuleRepo := new(MockRuleRepository)
	ruleService := service.NewRuleService(mockRuleRepo)
	db := setupTestDB()

	testUser := models.User{Email: "test@example.com"}
	db.Create(&testUser)

	handler := api.NewDeleteRuleHandler(ruleService, db)

	req, _ := http.NewRequest("DELETE", "/api/rules/invalid", nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = gin.Params{{Key: "id", Value: "invalid"}}
	c.Set("user_id", testUser.ID)
	c.Set("user_email", testUser.Email)
	c.Set("client_ip", "127.0.0.1")

	handler(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Contains(t, resp["code"], "INVALID_REQUEST")

	mockRuleRepo.AssertNotCalled(t, "Delete")
}

// TestNewDeleteRuleHandler_RuleNotFound tests deleting non-existent rule
func TestNewDeleteRuleHandler_RuleNotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockRuleRepo := new(MockRuleRepository)
	ruleService := service.NewRuleService(mockRuleRepo)
	db := setupTestDB()

	testUser := models.User{Email: "test@example.com"}
	db.Create(&testUser)

	mockRuleRepo.On("FindByID", mock.Anything, uint(999)).
		Return((*models.Rule)(nil), errors.New("rule not found")).Once()

	mockRuleRepo.On("Delete", mock.Anything, uint(999)).
		Return(errors.New("rule not found")).Once()

	handler := api.NewDeleteRuleHandler(ruleService, db)

	req, _ := http.NewRequest("DELETE", "/api/rules/999", nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = gin.Params{{Key: "id", Value: "999"}}
	c.Set("user_id", testUser.ID)
	c.Set("user_email", testUser.Email)
	c.Set("client_ip", "127.0.0.1")

	handler(c)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "RULE_NOT_FOUND", resp["code"])

	mockRuleRepo.AssertExpectations(t)
}

// TestNewDeleteRuleHandler_DatabaseError tests database deletion error
func TestNewDeleteRuleHandler_DatabaseError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockRuleRepo := new(MockRuleRepository)
	ruleService := service.NewRuleService(mockRuleRepo)
	db := setupTestDB()

	testUser := models.User{Email: "test@example.com"}
	db.Create(&testUser)

	existingRule := &models.Rule{
		ID:   1,
		Name: "Test",
	}

	mockRuleRepo.On("FindByID", mock.Anything, uint(1)).
		Return(existingRule, nil).Once()

	mockRuleRepo.On("Delete", mock.Anything, uint(1)).
		Return(errors.New("database error")).Once()

	handler := api.NewDeleteRuleHandler(ruleService, db)

	req, _ := http.NewRequest("DELETE", "/api/rules/1", nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = gin.Params{{Key: "id", Value: "1"}}
	c.Set("user_id", testUser.ID)
	c.Set("user_email", testUser.Email)
	c.Set("client_ip", "127.0.0.1")

	handler(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "DATABASE_ERROR", resp["code"])

	mockRuleRepo.AssertExpectations(t)
}

// TestNewToggleRuleHandler_Success tests successful rule toggle
func TestNewToggleRuleHandler_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockRuleRepo := new(MockRuleRepository)
	ruleService := service.NewRuleService(mockRuleRepo)

	existingRule := &models.Rule{
		ID:      1,
		Name:    "Test Rule",
		Enabled: true,
	}

	mockRuleRepo.On("FindByID", mock.Anything, uint(1)).
		Return(existingRule, nil).Once()

	mockRuleRepo.On("ToggleEnabled", mock.Anything, uint(1), false).
		Return(nil).Once()

	handler := api.NewToggleRuleHandler(ruleService)

	req, _ := http.NewRequest("PATCH", "/api/rules/1/toggle", nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = gin.Params{{Key: "id", Value: "1"}}

	handler(c)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "Rule toggled successfully", resp["message"])
	assert.Equal(t, false, resp["enabled"])

	mockRuleRepo.AssertExpectations(t)
}

// TestNewToggleRuleHandler_InvalidID tests with invalid rule ID
func TestNewToggleRuleHandler_InvalidID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockRuleRepo := new(MockRuleRepository)
	ruleService := service.NewRuleService(mockRuleRepo)

	handler := api.NewToggleRuleHandler(ruleService)

	req, _ := http.NewRequest("PATCH", "/api/rules/invalid/toggle", nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = gin.Params{{Key: "id", Value: "invalid"}}

	handler(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Contains(t, resp["code"], "INVALID_REQUEST")

	mockRuleRepo.AssertNotCalled(t, "FindByID")
}

// TestNewToggleRuleHandler_RuleNotFound tests toggling non-existent rule
func TestNewToggleRuleHandler_RuleNotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockRuleRepo := new(MockRuleRepository)
	ruleService := service.NewRuleService(mockRuleRepo)

	// Return nil, nil so service returns "rule not found" exactly
	mockRuleRepo.On("FindByID", mock.Anything, uint(999)).
		Return((*models.Rule)(nil), nil).Once()

	handler := api.NewToggleRuleHandler(ruleService)

	req, _ := http.NewRequest("PATCH", "/api/rules/999/toggle", nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = gin.Params{{Key: "id", Value: "999"}}

	handler(c)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "RULE_NOT_FOUND", resp["code"])

	mockRuleRepo.AssertExpectations(t)
}

// TestNewToggleRuleHandler_DatabaseError tests database toggle error
func TestNewToggleRuleHandler_DatabaseError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockRuleRepo := new(MockRuleRepository)
	ruleService := service.NewRuleService(mockRuleRepo)

	existingRule := &models.Rule{
		ID:      1,
		Enabled: true,
	}

	mockRuleRepo.On("FindByID", mock.Anything, uint(1)).
		Return(existingRule, nil).Once()

	mockRuleRepo.On("ToggleEnabled", mock.Anything, uint(1), false).
		Return(errors.New("database error")).Once()

	handler := api.NewToggleRuleHandler(ruleService)

	req, _ := http.NewRequest("PATCH", "/api/rules/1/toggle", nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = gin.Params{{Key: "id", Value: "1"}}

	handler(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "DATABASE_ERROR", resp["code"])

	mockRuleRepo.AssertExpectations(t)
}

// TestGetRulesByType tests the GetRulesByType function
func TestGetRulesByType(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db := setupTestDB()

	// Ensure Rule table is migrated
	db.AutoMigrate(&models.Rule{})

	// Create test rules
	rule1 := models.Rule{
		Name:    "XSS Rule 1",
		Pattern: "test1",
		Type:    "xss",
		Enabled: true,
	}
	rule2 := models.Rule{
		Name:    "XSS Rule 2",
		Pattern: "test2",
		Type:    "xss",
		Enabled: true,
	}
	rule3 := models.Rule{
		Name:    "SQL Injection Rule",
		Pattern: "test3",
		Type:    "sqli",
		Enabled: true,
	}
	rule4 := models.Rule{
		Name:    "Disabled XSS Rule",
		Pattern: "test4",
		Type:    "xss",
		Enabled: true, // Create as enabled first
	}

	result1 := db.Create(&rule1)
	require.NoError(t, result1.Error)
	result2 := db.Create(&rule2)
	require.NoError(t, result2.Error)
	result3 := db.Create(&rule3)
	require.NoError(t, result3.Error)
	result4 := db.Create(&rule4)
	require.NoError(t, result4.Error)

	// Now disable rule4 explicitly (GORM ignores false values on Create)
	db.Model(&rule4).Update("enabled", false)

	// Verify rule4 is actually disabled
	var checkRule models.Rule
	db.First(&checkRule, rule4.ID)
	assert.False(t, checkRule.Enabled, "Rule4 should be disabled")

	// Test GetRulesByType for XSS (should only find enabled ones)
	xssRules := api.GetRulesByType(db, "xss")
	assert.Equal(t, 2, len(xssRules), "Should find exactly 2 enabled XSS rules")

	// Test GetRulesByType for SQLI
	sqliRules := api.GetRulesByType(db, "sqli")
	assert.Equal(t, 1, len(sqliRules))

	// Test GetRulesByType for non-existent type
	lfiRules := api.GetRulesByType(db, "lfi")
	assert.Equal(t, 0, len(lfiRules))
}

// TestDeprecatedHandlers tests all deprecated handler functions
func TestDeprecatedHandlers(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name    string
		handler func(*gin.Context)
	}{
		{"GetRules", api.GetRules},
		{"CreateRule", api.CreateRule},
		{"UpdateRule", api.UpdateRule},
		{"DeleteRule", api.DeleteRule},
		{"ToggleRule", api.ToggleRule},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("GET", "/api/rules", nil)

			tt.handler(c)

			assert.Equal(t, http.StatusBadRequest, w.Code)

			var resp map[string]interface{}
			json.Unmarshal(w.Body.Bytes(), &resp)
			assert.Contains(t, resp["code"], "INVALID_REQUEST")
			assert.Contains(t, fmt.Sprint(resp["message"]), "use New")
		})
	}
}
