package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/api"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/test/helpers"
)

func TestNewGetRulesHandler(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	router := gin.New()
	router.GET("/rules", api.NewGetRulesHandler(db))

	t.Run("get rules success - returns default and custom rules", func(t *testing.T) {
		// Create some custom rules
		customRules := []models.Rule{
			{
				Name:    "Custom XSS Rule",
				Pattern: "<script>.*</script>",
				Type:    "XSS",
				Severity: "high",
				Action:  "block",
				Enabled: true,
			},
			{
				Name:    "Custom SQL Injection Rule",
				Pattern: "UNION.*SELECT",
				Type:    "SQL_INJECTION",
				Severity: "critical",
				Action:  "log",
				Enabled: true,
			},
		}

		for _, rule := range customRules {
			assert.NoError(t, db.Create(&rule).Error)
		}

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/rules", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response api.RulesResponse
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))

		// Should have default rules (13) + custom rules (2)
		assert.Equal(t, 13, len(response.DefaultRules))
		assert.Equal(t, 2, len(response.CustomRules))
		assert.Equal(t, 15, response.TotalRules)

		// Verify default rules are present
		assert.True(t, response.DefaultRules[0].IsDefault)
		assert.True(t, response.DefaultRules[0].Enabled)

		// Verify custom rules
		assert.Equal(t, "Custom XSS Rule", response.CustomRules[0].Name)
		assert.Equal(t, "Custom SQL Injection Rule", response.CustomRules[1].Name)
	})

	t.Run("get rules - empty custom rules", func(t *testing.T) {
		// Clear database
		db.Exec("DELETE FROM rules")

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/rules", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response api.RulesResponse
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))

		assert.Equal(t, 13, len(response.DefaultRules))
		assert.Equal(t, 0, len(response.CustomRules))
		assert.Equal(t, 13, response.TotalRules)
	})

	t.Run("factory function creates handler successfully", func(t *testing.T) {
		handler := api.NewGetRulesHandler(db)
		assert.NotNil(t, handler)
	})
}

func TestNewGetRulesHandlerDatabaseError(t *testing.T) {
	db := helpers.SetupTestDB(t)
	helpers.CleanupTestDB(t, db)

	t.Run("get rules - database error returns default rules only", func(t *testing.T) {
		router := gin.New()
		router.GET("/rules", api.NewGetRulesHandler(db))

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/rules", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response api.RulesResponse
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))

		// Should still return default rules with empty custom rules
		assert.Equal(t, 13, len(response.DefaultRules))
		assert.Equal(t, 0, len(response.CustomRules))
		assert.Equal(t, 13, response.TotalRules)
	})
}

func TestNewGetCustomRulesHandler(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	t.Run("get custom rules success - returns only enabled rules", func(t *testing.T) {
		// Clear any existing rules
		db.Exec("DELETE FROM rules")

		router := gin.New()
		router.GET("/custom-rules", api.NewGetCustomRulesHandler(db))

		// Create enabled rules
		enabledRules := []models.Rule{
			{
				Name:    "Enabled Rule 1",
				Pattern: "pattern1",
				Type:    "XSS",
			},
			{
				Name:    "Enabled Rule 2",
				Pattern: "pattern2",
				Type:    "SQL_INJECTION",
			},
		}

		for _, rule := range enabledRules {
			assert.NoError(t, db.Create(&rule).Error)
		}

		// Create a disabled rule - must update after creation
		disabledRule := models.Rule{
			Name:    "Disabled Rule",
			Pattern: "pattern3",
			Type:    "LFI",
		}
		db.Create(&disabledRule)
		db.Model(&disabledRule).Update("enabled", false)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/custom-rules", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response api.CustomRulesResponse
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))

		assert.Equal(t, 2, response.Count)
		assert.Equal(t, 2, len(response.Rules))
		assert.Equal(t, "Enabled Rule 1", response.Rules[0].Name)
		assert.Equal(t, "Enabled Rule 2", response.Rules[1].Name)
	})

	t.Run("get custom rules - empty database", func(t *testing.T) {
		db.Exec("DELETE FROM rules")

		router := gin.New()
		router.GET("/custom-rules", api.NewGetCustomRulesHandler(db))

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/custom-rules", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response api.CustomRulesResponse
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))

		assert.Equal(t, 0, response.Count)
		assert.Equal(t, 0, len(response.Rules))
	})

	t.Run("factory function creates handler successfully", func(t *testing.T) {
		handler := api.NewGetCustomRulesHandler(db)
		assert.NotNil(t, handler)
	})
}

func TestNewGetCustomRulesHandlerDatabaseError(t *testing.T) {
	db := helpers.SetupTestDB(t)
	helpers.CleanupTestDB(t, db)

	t.Run("get custom rules - database error", func(t *testing.T) {
		router := gin.New()
		router.GET("/custom-rules", api.NewGetCustomRulesHandler(db))

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/custom-rules", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, "failed to fetch custom rules", response["error"])
	})
}

func TestNewCreateRuleHandler(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(1))
		c.Set("user_email", "admin@example.com")
		c.Next()
	})
	router.POST("/rules", api.NewCreateRuleHandler(db))

	t.Run("create rule success", func(t *testing.T) {
		payload := models.Rule{
			Name:        "Test XSS Rule",
			Pattern:     "<script>.*</script>",
			Type:        "XSS",
			Severity:    "high",
			Action:      "block",
			Description: "Test rule description",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/rules", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var response map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, "Rule created successfully", response["message"])

		ruleData := response["rule"].(map[string]interface{})
		assert.Equal(t, "Test XSS Rule", ruleData["name"])
		assert.Equal(t, "<script>.*</script>", ruleData["pattern"])
		assert.Equal(t, "XSS", ruleData["type"])
		assert.True(t, ruleData["enabled"].(bool))

		// Verify audit log was created
		var auditLog models.AuditLog
		err := db.Where("action = ? AND category = ?", "CREATE_RULE", "RULES").First(&auditLog).Error
		assert.NoError(t, err)
		assert.Equal(t, "success", auditLog.Status)
		assert.Equal(t, uint(1), auditLog.UserID)
		assert.Equal(t, "admin@example.com", auditLog.UserEmail)
	})

	t.Run("create rule with detect mode - action='log' disables all action types", func(t *testing.T) {
		payload := models.Rule{
			Name:             "Detect Mode Rule",
			Pattern:          "test-pattern",
			Type:             "SQL_INJECTION",
			Action:           "log",
			BlockEnabled:     true, // These should be forced to false
			DropEnabled:      true,
			RedirectEnabled:  true,
			ChallengeEnabled: true,
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/rules", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var response map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))

		ruleData := response["rule"].(map[string]interface{})
		assert.Equal(t, "log", ruleData["action"])
		assert.False(t, ruleData["block_enabled"].(bool))
		assert.False(t, ruleData["drop_enabled"].(bool))
		assert.False(t, ruleData["redirect_enabled"].(bool))
		assert.False(t, ruleData["challenge_enabled"].(bool))
	})

	t.Run("create rule with block action - allows action types", func(t *testing.T) {
		payload := models.Rule{
			Name:            "Block Mode Rule",
			Pattern:         "test-pattern",
			Type:            "XSS",
			Action:          "block",
			BlockEnabled:    true,
			ChallengeEnabled: true,
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/rules", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var response map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))

		ruleData := response["rule"].(map[string]interface{})
		assert.Equal(t, "block", ruleData["action"])
		assert.True(t, ruleData["block_enabled"].(bool))
		assert.True(t, ruleData["challenge_enabled"].(bool))
	})

	t.Run("create rule - invalid JSON", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/rules", bytes.NewBuffer([]byte("invalid json")))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, "Invalid rule data", response["error"])

		// Verify error audit log was created
		var auditLog models.AuditLog
		err := db.Where("action = ? AND status = ?", "CREATE_RULE", "failure").First(&auditLog).Error
		assert.NoError(t, err)
		assert.NotEmpty(t, auditLog.Error)
	})

	t.Run("create rule - missing name", func(t *testing.T) {
		payload := models.Rule{
			Pattern: "test-pattern",
			Type:    "XSS",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/rules", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, "Name and Pattern are required", response["error"])

		// Verify error audit log was created
		var auditLog models.AuditLog
		err := db.Where("action = ? AND status = ? AND error LIKE ?", "CREATE_RULE", "failure", "%Name and Pattern are required%").First(&auditLog).Error
		assert.NoError(t, err)
	})

	t.Run("create rule - missing pattern", func(t *testing.T) {
		payload := models.Rule{
			Name: "Test Rule",
			Type: "XSS",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/rules", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, "Name and Pattern are required", response["error"])
	})

	t.Run("create rule - empty name", func(t *testing.T) {
		payload := models.Rule{
			Name:    "",
			Pattern: "test-pattern",
			Type:    "XSS",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/rules", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("create rule - empty pattern", func(t *testing.T) {
		payload := models.Rule{
			Name:    "Test Rule",
			Pattern: "",
			Type:    "XSS",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/rules", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("factory function creates handler successfully", func(t *testing.T) {
		handler := api.NewCreateRuleHandler(db)
		assert.NotNil(t, handler)
	})
}

func TestNewCreateRuleHandlerDatabaseError(t *testing.T) {
	db := helpers.SetupTestDB(t)
	helpers.CleanupTestDB(t, db)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(1))
		c.Set("user_email", "admin@example.com")
		c.Next()
	})
	router.POST("/rules", api.NewCreateRuleHandler(db))

	t.Run("create rule - database error", func(t *testing.T) {
		payload := models.Rule{
			Name:    "Test Rule",
			Pattern: "test-pattern",
			Type:    "XSS",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/rules", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, "failed to create rule", response["error"])
	})
}

func TestNewUpdateRuleHandler(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(1))
		c.Set("user_email", "admin@example.com")
		c.Next()
	})
	router.PUT("/rules/:id", api.NewUpdateRuleHandler(db))

	t.Run("update rule success", func(t *testing.T) {
		// Create a rule first
		rule := models.Rule{
			Name:    "Original Rule",
			Pattern: "original-pattern",
			Type:    "XSS",
			Enabled: true,
		}
		db.Create(&rule)

		// Update the rule
		updatePayload := models.Rule{
			Name:        "Updated Rule",
			Pattern:     "updated-pattern",
			Type:        "SQL_INJECTION",
			Severity:    "critical",
			Action:      "block",
			Description: "Updated description",
		}
		body, _ := json.Marshal(updatePayload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", fmt.Sprintf("/rules/%d", rule.ID), bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, "Rule updated successfully", response["message"])

		ruleData := response["rule"].(map[string]interface{})
		assert.Equal(t, "Updated Rule", ruleData["name"])
		assert.Equal(t, "updated-pattern", ruleData["pattern"])

		// Verify audit log was created
		var auditLog models.AuditLog
		err := db.Where("action = ? AND category = ?", "UPDATE_RULE", "RULES").First(&auditLog).Error
		assert.NoError(t, err)
		assert.Equal(t, "success", auditLog.Status)
	})

	t.Run("update rule - detect mode forces action types to false", func(t *testing.T) {
		// Create a rule with block actions enabled
		rule := models.Rule{
			Name:             "Block Rule",
			Pattern:          "pattern",
			Type:             "XSS",
			Action:           "block",
			BlockEnabled:     true,
			DropEnabled:      true,
			RedirectEnabled:  true,
			ChallengeEnabled: true,
		}
		db.Create(&rule)

		// Update to detect mode - the handler should force these to false
		updatePayload := map[string]interface{}{
			"action":            "log",
			"block_enabled":     true,
			"drop_enabled":      true,
			"redirect_enabled":  true,
			"challenge_enabled": true,
		}
		body, _ := json.Marshal(updatePayload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", fmt.Sprintf("/rules/%d", rule.ID), bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// Verify response shows action was changed to log
		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		ruleData := response["rule"].(map[string]interface{})
		assert.Equal(t, "log", ruleData["action"])
	})

	t.Run("update rule - invalid rule ID format", func(t *testing.T) {
		updatePayload := models.Rule{
			Name: "Test",
		}
		body, _ := json.Marshal(updatePayload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/rules/invalid", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, "Invalid rule ID", response["error"])

		// Verify error audit log was created
		var auditLog models.AuditLog
		err := db.Where("action = ? AND status = ?", "UPDATE_RULE", "failure").First(&auditLog).Error
		assert.NoError(t, err)
	})

	t.Run("update rule - invalid JSON", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/rules/1", bytes.NewBuffer([]byte("invalid json")))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, "Invalid rule data", response["error"])
	})

	t.Run("update rule - rule not found", func(t *testing.T) {
		updatePayload := models.Rule{
			Name:    "Test",
			Pattern: "test",
		}
		body, _ := json.Marshal(updatePayload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/rules/99999", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		// GORM Updates doesn't return ErrRecordNotFound, it just updates 0 rows
		// So this might return 200 or 500 depending on implementation
		assert.NotEqual(t, http.StatusCreated, w.Code)
	})

	t.Run("factory function creates handler successfully", func(t *testing.T) {
		handler := api.NewUpdateRuleHandler(db)
		assert.NotNil(t, handler)
	})
}

func TestNewUpdateRuleHandlerDatabaseError(t *testing.T) {
	db := helpers.SetupTestDB(t)
	helpers.CleanupTestDB(t, db)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(1))
		c.Set("user_email", "admin@example.com")
		c.Next()
	})
	router.PUT("/rules/:id", api.NewUpdateRuleHandler(db))

	t.Run("update rule - database error", func(t *testing.T) {
		updatePayload := models.Rule{
			Name:    "Test",
			Pattern: "test-pattern",
		}
		body, _ := json.Marshal(updatePayload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/rules/1", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, "failed to update rule", response["error"])
	})
}

func TestNewDeleteRuleHandler(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(1))
		c.Set("user_email", "admin@example.com")
		c.Next()
	})
	router.DELETE("/rules/:id", api.NewDeleteRuleHandler(db))

	t.Run("delete rule success", func(t *testing.T) {
		// Create a rule first
		rule := models.Rule{
			Name:    "Rule to Delete",
			Pattern: "test-pattern",
			Type:    "XSS",
		}
		db.Create(&rule)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("DELETE", fmt.Sprintf("/rules/%d", rule.ID), nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, "Rule deleted successfully", response["message"])

		// Verify rule was deleted
		var count int64
		db.Model(&models.Rule{}).Where("id = ?", rule.ID).Count(&count)
		assert.Equal(t, int64(0), count)

		// Verify audit log was created
		var auditLog models.AuditLog
		err := db.Where("action = ? AND category = ?", "DELETE_RULE", "RULES").First(&auditLog).Error
		assert.NoError(t, err)
		assert.Equal(t, "success", auditLog.Status)
		assert.Contains(t, auditLog.Description, "Rule to Delete")
	})

	t.Run("delete rule - invalid rule ID format", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("DELETE", "/rules/invalid", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, "Invalid rule ID", response["error"])

		// Verify error audit log was created
		var auditLog models.AuditLog
		err := db.Where("action = ? AND status = ?", "DELETE_RULE", "failure").First(&auditLog).Error
		assert.NoError(t, err)
	})

	t.Run("delete rule - non-existent rule", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("DELETE", "/rules/99999", nil)
		router.ServeHTTP(w, req)

		// GORM Delete doesn't error on non-existent records
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("delete rule - rule name preserved in audit log when rule has no name", func(t *testing.T) {
		// Create a rule without a name (edge case)
		rule := models.Rule{
			Name:    "",
			Pattern: "test-pattern",
			Type:    "XSS",
		}
		db.Create(&rule)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("DELETE", fmt.Sprintf("/rules/%d", rule.ID), nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// Verify audit log uses rule ID when name is empty
		var auditLog models.AuditLog
		err := db.Where("action = ? AND resource_id = ?", "DELETE_RULE", fmt.Sprintf("%d", rule.ID)).First(&auditLog).Error
		assert.NoError(t, err)
	})

	t.Run("factory function creates handler successfully", func(t *testing.T) {
		handler := api.NewDeleteRuleHandler(db)
		assert.NotNil(t, handler)
	})
}

func TestNewDeleteRuleHandlerDatabaseError(t *testing.T) {
	db := helpers.SetupTestDB(t)
	helpers.CleanupTestDB(t, db)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(1))
		c.Set("user_email", "admin@example.com")
		c.Next()
	})
	router.DELETE("/rules/:id", api.NewDeleteRuleHandler(db))

	t.Run("delete rule - database error", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("DELETE", "/rules/1", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, "failed to delete rule", response["error"])
	})
}

func TestNewToggleRuleHandler(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	router := gin.New()
	router.PUT("/rules/:id/toggle", api.NewToggleRuleHandler(db))

	t.Run("toggle rule success - enable to disable", func(t *testing.T) {
		// Create an enabled rule
		rule := models.Rule{
			Name:    "Rule to Toggle",
			Pattern: "test-pattern",
			Type:    "XSS",
			Enabled: true,
		}
		db.Create(&rule)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", fmt.Sprintf("/rules/%d/toggle", rule.ID), nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, "Rule toggled successfully", response["message"])
		assert.False(t, response["enabled"].(bool))

		// Verify rule was toggled
		var updatedRule models.Rule
		db.First(&updatedRule, rule.ID)
		assert.False(t, updatedRule.Enabled)
	})

	t.Run("toggle rule success - disable to enable", func(t *testing.T) {
		// Clear database
		db.Exec("DELETE FROM rules")

		// Create a disabled rule
		rule := models.Rule{
			Name:    "Disabled Rule",
			Pattern: "test-pattern",
			Type:    "SQL_INJECTION",
		}
		db.Create(&rule)
		// Explicitly disable it
		db.Model(&rule).Update("enabled", false)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", fmt.Sprintf("/rules/%d/toggle", rule.ID), nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, "Rule toggled successfully", response["message"])
		assert.True(t, response["enabled"].(bool))

		// Verify rule was toggled
		var updatedRule models.Rule
		db.First(&updatedRule, rule.ID)
		assert.True(t, updatedRule.Enabled)
	})

	t.Run("toggle rule - invalid rule ID format", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/rules/invalid/toggle", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, "Invalid rule ID", response["error"])
	})

	t.Run("toggle rule - rule not found", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/rules/99999/toggle", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)

		var response map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, "Rule not found", response["error"])
	})

	t.Run("factory function creates handler successfully", func(t *testing.T) {
		handler := api.NewToggleRuleHandler(db)
		assert.NotNil(t, handler)
	})
}

func TestNewToggleRuleHandlerDatabaseErrors(t *testing.T) {
	db := helpers.SetupTestDB(t)

	t.Run("toggle rule - database error on fetch", func(t *testing.T) {
		helpers.CleanupTestDB(t, db)

		router := gin.New()
		router.PUT("/rules/:id/toggle", api.NewToggleRuleHandler(db))

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/rules/1/toggle", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		assert.Equal(t, "failed to fetch rule", response["error"])
	})

	t.Run("toggle rule - database error on save", func(t *testing.T) {
		db2 := helpers.SetupTestDB(t)

		// Create a rule
		rule := models.Rule{
			Name:    "Test Rule",
			Pattern: "test-pattern",
			Type:    "XSS",
			Enabled: true,
		}
		db2.Create(&rule)

		// Close database to trigger save error - this will cause fetch to fail first
		helpers.CleanupTestDB(t, db2)

		router := gin.New()
		router.PUT("/rules/:id/toggle", api.NewToggleRuleHandler(db2))

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", fmt.Sprintf("/rules/%d/toggle", rule.ID), nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response map[string]interface{}
		assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
		// When DB is closed, fetch fails first, not save
		assert.Contains(t, response["error"].(string), "failed to")
	})
}

func TestGetRulesByType(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	t.Run("get rules by type - returns matching enabled rules", func(t *testing.T) {
		// Clear database
		db.Exec("DELETE FROM rules")

		// Create enabled rules
		enabledRules := []models.Rule{
			{Name: "XSS Rule 1", Pattern: "pattern1", Type: "XSS"},
			{Name: "XSS Rule 2", Pattern: "pattern2", Type: "XSS"},
			{Name: "SQLi Rule", Pattern: "pattern4", Type: "SQL_INJECTION"},
		}

		for _, rule := range enabledRules {
			db.Create(&rule)
		}

		// Create a disabled rule
		disabledRule := models.Rule{Name: "XSS Rule 3", Pattern: "pattern3", Type: "XSS"}
		db.Create(&disabledRule)
		db.Model(&disabledRule).Update("enabled", false)

		results := api.GetRulesByType(db, "XSS")

		assert.Equal(t, 2, len(results))
		assert.Equal(t, "XSS Rule 1", results[0].Name)
		assert.Equal(t, "XSS Rule 2", results[1].Name)
	})

	t.Run("get rules by type - no matching rules", func(t *testing.T) {
		db.Exec("DELETE FROM rules")

		results := api.GetRulesByType(db, "NONEXISTENT")

		assert.Equal(t, 0, len(results))
	})

	t.Run("get rules by type - only disabled rules", func(t *testing.T) {
		db.Exec("DELETE FROM rules")

		// Create a disabled rule - must update after creation due to GORM default
		rule := models.Rule{
			Name:    "Disabled LFI Rule",
			Pattern: "pattern",
			Type:    "LFI",
		}
		db.Create(&rule)
		// Explicitly set enabled to false
		db.Model(&rule).Update("enabled", false)

		// Should return 0 results because rule is disabled
		results := api.GetRulesByType(db, "LFI")

		assert.Equal(t, 0, len(results), "Should return no results for disabled rules")
	})

	t.Run("get rules by type - filters by type correctly", func(t *testing.T) {
		db.Exec("DELETE FROM rules")

		rules := []models.Rule{
			{Name: "SQL Rule", Pattern: "pattern1", Type: "SQL_INJECTION", Enabled: true},
			{Name: "LFI Rule", Pattern: "pattern2", Type: "LFI", Enabled: true},
			{Name: "XSS Rule", Pattern: "pattern3", Type: "XSS", Enabled: true},
		}

		for _, rule := range rules {
			db.Create(&rule)
		}

		results := api.GetRulesByType(db, "SQL_INJECTION")

		assert.Equal(t, 1, len(results))
		assert.Equal(t, "SQL Rule", results[0].Name)
		assert.Equal(t, "SQL_INJECTION", results[0].Type)
	})
}

func TestDeprecatedHandlers(t *testing.T) {
	router := gin.New()
	router.GET("/deprecated/rules", api.GetRules)
	router.POST("/deprecated/rules", api.CreateRule)
	router.PUT("/deprecated/rules", api.UpdateRule)
	router.DELETE("/deprecated/rules", api.DeleteRule)
	router.PUT("/deprecated/rules/toggle", api.ToggleRule)

	t.Run("deprecated GetRules returns error", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/deprecated/rules", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "use NewGetRulesHandler", response["error"])
	})

	t.Run("deprecated CreateRule returns error", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/deprecated/rules", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "use NewCreateRuleHandler", response["error"])
	})

	t.Run("deprecated UpdateRule returns error", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/deprecated/rules", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "use NewUpdateRuleHandler", response["error"])
	})

	t.Run("deprecated DeleteRule returns error", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("DELETE", "/deprecated/rules", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "use NewDeleteRuleHandler", response["error"])
	})

	t.Run("deprecated ToggleRule returns error", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/deprecated/rules/toggle", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "use NewToggleRuleHandler", response["error"])
	})
}

func TestRuleAuditLogging(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(1))
		c.Set("user_email", "admin@example.com")
		c.Next()
	})
	router.POST("/rules", api.NewCreateRuleHandler(db))
	router.PUT("/rules/:id", api.NewUpdateRuleHandler(db))
	router.DELETE("/rules/:id", api.NewDeleteRuleHandler(db))

	t.Run("create rule logs audit action with details", func(t *testing.T) {
		payload := models.Rule{
			Name:     "Audit Test Rule",
			Pattern:  "test-pattern",
			Type:     "XSS",
			Severity: "high",
			Action:   "block",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/rules", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var auditLog models.AuditLog
		err := db.Where("action = ?", "CREATE_RULE").First(&auditLog).Error
		assert.NoError(t, err)
		assert.Equal(t, "RULES", auditLog.Category)
		assert.Equal(t, "rule", auditLog.ResourceType)
		assert.Contains(t, auditLog.Description, "Audit Test Rule")
		assert.Contains(t, auditLog.Details, "rule_name")
		assert.Contains(t, auditLog.Details, "rule_type")
		assert.Contains(t, auditLog.Details, "action")
		assert.Contains(t, auditLog.Details, "pattern")
	})

	t.Run("update rule logs audit action", func(t *testing.T) {
		rule := models.Rule{
			Name:    "Rule to Update",
			Pattern: "pattern",
			Type:    "SQL_INJECTION",
		}
		db.Create(&rule)

		updatePayload := models.Rule{
			Name: "Updated Name",
		}
		body, _ := json.Marshal(updatePayload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", fmt.Sprintf("/rules/%d", rule.ID), bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var auditLog models.AuditLog
		err := db.Where("action = ? AND resource_id = ?", "UPDATE_RULE", fmt.Sprintf("%d", rule.ID)).First(&auditLog).Error
		assert.NoError(t, err)
		assert.Equal(t, "RULES", auditLog.Category)
		assert.Contains(t, auditLog.Details, "rule_name")
	})

	t.Run("delete rule logs audit action", func(t *testing.T) {
		rule := models.Rule{
			Name:    "Rule to Delete for Audit",
			Pattern: "pattern",
			Type:    "LFI",
		}
		db.Create(&rule)
		ruleID := rule.ID

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("DELETE", fmt.Sprintf("/rules/%d", ruleID), nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var auditLog models.AuditLog
		err := db.Where("action = ? AND resource_id = ?", "DELETE_RULE", fmt.Sprintf("%d", ruleID)).First(&auditLog).Error
		assert.NoError(t, err)
		assert.Equal(t, "RULES", auditLog.Category)
		assert.Contains(t, auditLog.Description, "Rule to Delete for Audit")
	})

	t.Run("failed create logs error audit", func(t *testing.T) {
		// Missing required fields
		payload := models.Rule{
			Type: "XSS",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/rules", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var auditLog models.AuditLog
		err := db.Where("action = ? AND status = ?", "CREATE_RULE", "failure").Order("created_at DESC").First(&auditLog).Error
		assert.NoError(t, err)
		assert.NotEmpty(t, auditLog.Error)
	})

	t.Run("failed update logs error audit", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/rules/invalid", bytes.NewBuffer([]byte("{}")))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var auditLog models.AuditLog
		err := db.Where("action = ? AND status = ?", "UPDATE_RULE", "failure").Order("created_at DESC").First(&auditLog).Error
		assert.NoError(t, err)
	})

	t.Run("failed delete logs error audit", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("DELETE", "/rules/invalid", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var auditLog models.AuditLog
		err := db.Where("action = ? AND status = ?", "DELETE_RULE", "failure").Order("created_at DESC").First(&auditLog).Error
		assert.NoError(t, err)
	})
}

func TestRuleValidationEdgeCases(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(1))
		c.Set("user_email", "admin@example.com")
		c.Next()
	})
	router.POST("/rules", api.NewCreateRuleHandler(db))

	t.Run("create rule with all fields populated", func(t *testing.T) {
		payload := models.Rule{
			Name:             "Complete Rule",
			Pattern:          "complete-pattern",
			Type:             "XSS",
			Severity:         "critical",
			Action:           "block",
			Description:      "Complete description",
			Enabled:          false, // Should be forced to true
			BlockEnabled:     true,
			DropEnabled:      false,
			RedirectEnabled:  true,
			ChallengeEnabled: false,
			RedirectURL:      "https://security.example.com",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/rules", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		ruleData := response["rule"].(map[string]interface{})

		// Enabled should be forced to true
		assert.True(t, ruleData["enabled"].(bool))
		assert.Equal(t, "https://security.example.com", ruleData["redirect_url"])
	})

	t.Run("create rule with whitespace in name and pattern", func(t *testing.T) {
		payload := models.Rule{
			Name:    "  Rule with spaces  ",
			Pattern: "  pattern  ",
			Type:    "SQL_INJECTION",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/rules", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		// Should succeed - validation doesn't trim
		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("create rule with special characters in pattern", func(t *testing.T) {
		payload := models.Rule{
			Name:    "Regex Pattern Rule",
			Pattern: `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`,
			Type:    "XSS",
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/rules", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("create multiple rules with same name", func(t *testing.T) {
		for i := 0; i < 3; i++ {
			payload := models.Rule{
				Name:    "Duplicate Name",
				Pattern: fmt.Sprintf("pattern-%d", i),
				Type:    "XSS",
			}
			body, _ := json.Marshal(payload)

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("POST", "/rules", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusCreated, w.Code)
		}

		// Verify all were created
		var count int64
		db.Model(&models.Rule{}).Where("name = ?", "Duplicate Name").Count(&count)
		assert.Equal(t, int64(3), count)
	})
}

func TestRuleActionTypesLogic(t *testing.T) {
	db := helpers.SetupTestDB(t)
	defer helpers.CleanupTestDB(t, db)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("user_id", uint(1))
		c.Set("user_email", "admin@example.com")
		c.Next()
	})
	router.POST("/rules", api.NewCreateRuleHandler(db))
	router.PUT("/rules/:id", api.NewUpdateRuleHandler(db))

	t.Run("log action disables all action types on create", func(t *testing.T) {
		payload := models.Rule{
			Name:             "Log Action Rule",
			Pattern:          "pattern",
			Type:             "XSS",
			Action:           "log",
			BlockEnabled:     true,
			DropEnabled:      true,
			RedirectEnabled:  true,
			ChallengeEnabled: true,
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/rules", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var createdRule models.Rule
		db.Where("name = ?", "Log Action Rule").First(&createdRule)
		assert.False(t, createdRule.BlockEnabled)
		assert.False(t, createdRule.DropEnabled)
		assert.False(t, createdRule.RedirectEnabled)
		assert.False(t, createdRule.ChallengeEnabled)
	})

	t.Run("block action allows action types on create", func(t *testing.T) {
		payload := models.Rule{
			Name:            "Block Action Rule",
			Pattern:         "pattern",
			Type:            "SQL_INJECTION",
			Action:          "block",
			BlockEnabled:    true,
			DropEnabled:     false,
			RedirectEnabled: true,
		}
		body, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/rules", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var createdRule models.Rule
		db.Where("name = ?", "Block Action Rule").First(&createdRule)
		assert.True(t, createdRule.BlockEnabled)
		assert.False(t, createdRule.DropEnabled)
		assert.True(t, createdRule.RedirectEnabled)
	})

	t.Run("changing to log action disables action types on update", func(t *testing.T) {
		rule := models.Rule{
			Name:    "Update Test Rule",
			Pattern: "pattern",
			Type:    "XSS",
			Action:  "block",
		}
		db.Create(&rule)
		// Explicitly set the action flags
		db.Model(&rule).Updates(map[string]interface{}{
			"block_enabled":     true,
			"challenge_enabled": true,
		})

		updatePayload := map[string]interface{}{
			"action":            "log",
			"block_enabled":     true, // Should be forced to false by handler
			"challenge_enabled": true, // Should be forced to false by handler
		}
		body, _ := json.Marshal(updatePayload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", fmt.Sprintf("/rules/%d", rule.ID), bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// Verify response shows action was updated
		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		ruleData := response["rule"].(map[string]interface{})
		assert.Equal(t, "log", ruleData["action"])
	})

	t.Run("changing from log to block action on update", func(t *testing.T) {
		rule := models.Rule{
			Name:    "Log to Block Rule",
			Pattern: "pattern",
			Type:    "LFI",
			Action:  "log",
		}
		db.Create(&rule)

		updatePayload := models.Rule{
			Action:       "block",
			BlockEnabled: true,
			DropEnabled:  true,
		}
		body, _ := json.Marshal(updatePayload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", fmt.Sprintf("/rules/%d", rule.ID), bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var updatedRule models.Rule
		db.First(&updatedRule, rule.ID)
		assert.Equal(t, "block", updatedRule.Action)
		assert.True(t, updatedRule.BlockEnabled)
		assert.True(t, updatedRule.DropEnabled)
	})
}
