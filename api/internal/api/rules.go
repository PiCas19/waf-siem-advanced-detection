package api

import (
	"fmt"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"gorm.io/gorm"
)

// RulesResponse contiene sia le regole default che custom
type RulesResponse struct {
	DefaultRules []DefaultRule  `json:"default_rules"`
	CustomRules  []models.Rule  `json:"custom_rules"`
	TotalRules   int            `json:"total_rules"`
}

// CustomRulesResponse contiene solo le regole custom per il WAF
type CustomRulesResponse struct {
	Rules []models.Rule `json:"rules"`
	Count int           `json:"count"`
}

// GetRules - Ritorna sia le regole di default che quelle custom dal database
func NewGetRulesHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Leggi regole di default
		defaultRules := GetDefaultRules()

		// Leggi regole custom dal database
		var customRules []models.Rule
		if err := db.Find(&customRules).Error; err != nil {
			fmt.Printf("[ERROR] Failed to fetch custom rules: %v\n", err)
			customRules = []models.Rule{}
		}

		response := RulesResponse{
			DefaultRules: defaultRules,
			CustomRules:  customRules,
			TotalRules:   len(defaultRules) + len(customRules),
		}

		c.JSON(200, response)
	}
}

// GetCustomRules - Ritorna solo le regole custom abilitate per il WAF
func NewGetCustomRulesHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var customRules []models.Rule
		if err := db.Where("enabled = ?", true).Find(&customRules).Error; err != nil {
			fmt.Printf("[ERROR] Failed to fetch custom rules: %v\n", err)
			c.JSON(500, gin.H{"error": "failed to fetch custom rules"})
			return
		}

		response := CustomRulesResponse{
			Rules: customRules,
			Count: len(customRules),
		}

		c.JSON(200, response)
	}
}

// CreateRule - Crea una nuova regola WAF nel database
func NewCreateRuleHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var rule models.Rule
		userID, _ := c.Get("user_id")
		userEmail, _ := c.Get("user_email")

		if err := c.ShouldBindJSON(&rule); err != nil {
			// Log failed rule creation - invalid request
			LogAuditActionWithError(db, userID.(uint), userEmail.(string), "CREATE_RULE", "RULES",
				"rule", "unknown", "Failed to create rule - invalid request format",
				err.Error(), c.ClientIP())
			fmt.Printf("[ERROR] Failed to parse rule: %v\n", err)
			c.JSON(400, gin.H{"error": "Invalid rule data"})
			return
		}

		if rule.Name == "" || rule.Pattern == "" {
			// Log failed rule creation - missing required fields
			LogAuditActionWithError(db, userID.(uint), userEmail.(string), "CREATE_RULE", "RULES",
				"rule", "unknown", "Failed to create rule - missing required fields",
				"Name and Pattern are required", c.ClientIP())
			c.JSON(400, gin.H{"error": "Name and Pattern are required"})
			return
		}

		rule.Enabled = true

		// Se la regola è in modalità "detect" (action='log'), forza tutti gli *Enabled a false
		if rule.Action == "log" {
			rule.BlockEnabled = false
			rule.DropEnabled = false
			rule.RedirectEnabled = false
			rule.ChallengeEnabled = false
		}

		if err := db.Create(&rule).Error; err != nil {
			// Log failed rule creation - database error
			LogAuditActionWithError(db, userID.(uint), userEmail.(string), "CREATE_RULE", "RULES",
				"rule", rule.Name, "Failed to create rule in database",
				err.Error(), c.ClientIP())
			fmt.Printf("[ERROR] Failed to create rule: %v\n", err)
			c.JSON(500, gin.H{"error": "failed to create rule"})
			return
		}

		// Log successful rule creation
		details := map[string]interface{}{
			"rule_name": rule.Name,
			"rule_type": rule.Type,
			"action":    rule.Action,
			"pattern":   rule.Pattern,
		}
		LogAuditAction(db, userID.(uint), userEmail.(string), "CREATE_RULE", "RULES",
			"rule", fmt.Sprintf("%d", rule.ID), fmt.Sprintf("Created rule '%s' with type '%s' and action '%s'", rule.Name, rule.Type, rule.Action),
			details, c.ClientIP())

		fmt.Printf("[INFO] Rule created: ID=%d, Name=%s, Type=%s, Action=%s\n", rule.ID, rule.Name, rule.Type, rule.Action)

		c.JSON(201, gin.H{
			"message": "Rule created successfully",
			"rule":    rule,
		})
	}
}

// UpdateRule - Modifica una regola esistente nel database
func NewUpdateRuleHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		ruleID := c.Param("id")
		id, err := strconv.ParseUint(ruleID, 10, 32)
		userID, _ := c.Get("user_id")
		userEmail, _ := c.Get("user_email")

		if err != nil {
			LogAuditActionWithError(db, userID.(uint), userEmail.(string), "UPDATE_RULE", "RULES",
				"rule", ruleID, "Failed to update rule - invalid rule ID format",
				"Invalid rule ID", c.ClientIP())
			c.JSON(400, gin.H{"error": "Invalid rule ID"})
			return
		}

		var updatedRule models.Rule
		if err := c.ShouldBindJSON(&updatedRule); err != nil {
			LogAuditActionWithError(db, userID.(uint), userEmail.(string), "UPDATE_RULE", "RULES",
				"rule", ruleID, "Failed to update rule - invalid request format",
				err.Error(), c.ClientIP())
			c.JSON(400, gin.H{"error": "Invalid rule data"})
			return
		}

		// Se la regola è in modalità "detect" (action='log'), forza tutti gli *Enabled a false
		if updatedRule.Action == "log" {
			updatedRule.BlockEnabled = false
			updatedRule.DropEnabled = false
			updatedRule.RedirectEnabled = false
			updatedRule.ChallengeEnabled = false
		}

		// Update the rule
		if err := db.Model(&models.Rule{}).Where("id = ?", uint(id)).Updates(updatedRule).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				LogAuditActionWithError(db, userID.(uint), userEmail.(string), "UPDATE_RULE", "RULES",
					"rule", ruleID, "Failed to update rule - rule not found",
					"Rule not found", c.ClientIP())
				c.JSON(404, gin.H{"error": "Rule not found"})
			} else {
				LogAuditActionWithError(db, userID.(uint), userEmail.(string), "UPDATE_RULE", "RULES",
					"rule", ruleID, "Failed to update rule in database",
					err.Error(), c.ClientIP())
				fmt.Printf("[ERROR] Failed to update rule: %v\n", err)
				c.JSON(500, gin.H{"error": "failed to update rule"})
			}
			return
		}

		// Fetch the updated rule
		var rule models.Rule
		db.First(&rule, uint(id))

		// Log successful rule update
		details := map[string]interface{}{
			"rule_name": rule.Name,
			"rule_type": rule.Type,
			"action":    rule.Action,
		}
		LogAuditAction(db, userID.(uint), userEmail.(string), "UPDATE_RULE", "RULES",
			"rule", ruleID, fmt.Sprintf("Updated rule '%s'", rule.Name),
			details, c.ClientIP())

		fmt.Printf("[INFO] Rule updated: ID=%d, Name=%s\n", rule.ID, rule.Name)

		c.JSON(200, gin.H{
			"message": "Rule updated successfully",
			"rule":    rule,
		})
	}
}

// DeleteRule - Elimina una regola dal database
func NewDeleteRuleHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		ruleID := c.Param("id")
		id, err := strconv.ParseUint(ruleID, 10, 32)
		userID, _ := c.Get("user_id")
		userEmail, _ := c.Get("user_email")

		if err != nil {
			LogAuditActionWithError(db, userID.(uint), userEmail.(string), "DELETE_RULE", "RULES",
				"rule", ruleID, "Failed to delete rule - invalid rule ID format",
				"Invalid rule ID", c.ClientIP())
			c.JSON(400, gin.H{"error": "Invalid rule ID"})
			return
		}

		// Fetch rule name before deletion for audit log
		var rule models.Rule
		db.First(&rule, uint(id))
		ruleName := rule.Name
		if ruleName == "" {
			ruleName = ruleID
		}

		if err := db.Delete(&models.Rule{}, uint(id)).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				LogAuditActionWithError(db, userID.(uint), userEmail.(string), "DELETE_RULE", "RULES",
					"rule", ruleID, "Failed to delete rule - rule not found",
					"Rule not found", c.ClientIP())
				c.JSON(404, gin.H{"error": "Rule not found"})
			} else {
				LogAuditActionWithError(db, userID.(uint), userEmail.(string), "DELETE_RULE", "RULES",
					"rule", ruleID, "Failed to delete rule from database",
					err.Error(), c.ClientIP())
				fmt.Printf("[ERROR] Failed to delete rule: %v\n", err)
				c.JSON(500, gin.H{"error": "failed to delete rule"})
			}
			return
		}

		// Log successful rule deletion
		LogAuditAction(db, userID.(uint), userEmail.(string), "DELETE_RULE", "RULES",
			"rule", ruleID, fmt.Sprintf("Deleted rule '%s'", ruleName),
			map[string]interface{}{"rule_name": ruleName}, c.ClientIP())

		fmt.Printf("[INFO] Rule deleted: ID=%s\n", ruleID)

		c.JSON(200, gin.H{"message": "Rule deleted successfully"})
	}
}

// ToggleRule - Abilita/Disabilita una regola nel database
func NewToggleRuleHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		ruleID := c.Param("id")
		id, err := strconv.ParseUint(ruleID, 10, 32)
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid rule ID"})
			return
		}

		var rule models.Rule
		if err := db.First(&rule, uint(id)).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				c.JSON(404, gin.H{"error": "Rule not found"})
			} else {
				fmt.Printf("[ERROR] Failed to fetch rule: %v\n", err)
				c.JSON(500, gin.H{"error": "failed to fetch rule"})
			}
			return
		}

		rule.Enabled = !rule.Enabled
		if err := db.Save(&rule).Error; err != nil {
			fmt.Printf("[ERROR] Failed to toggle rule: %v\n", err)
			c.JSON(500, gin.H{"error": "failed to toggle rule"})
			return
		}

		fmt.Printf("[INFO] Rule toggled: ID=%d, Enabled=%v\n", rule.ID, rule.Enabled)

		c.JSON(200, gin.H{
			"message": "Rule toggled successfully",
			"enabled": rule.Enabled,
		})
	}
}

// GetRulesByType - Ritorna le regole per un tipo di minaccia specifico
func GetRulesByType(db *gorm.DB, threatType string) []models.Rule {
	var matchingRules []models.Rule
	db.Where("type = ? AND enabled = ?", threatType, true).Find(&matchingRules)
	return matchingRules
}

// Deprecated handlers for backward compatibility
func GetRules(c *gin.Context)     { c.JSON(400, gin.H{"error": "use NewGetRulesHandler"}) }
func CreateRule(c *gin.Context)   { c.JSON(400, gin.H{"error": "use NewCreateRuleHandler"}) }
func UpdateRule(c *gin.Context)   { c.JSON(400, gin.H{"error": "use NewUpdateRuleHandler"}) }
func DeleteRule(c *gin.Context)   { c.JSON(400, gin.H{"error": "use NewDeleteRuleHandler"}) }
func ToggleRule(c *gin.Context)   { c.JSON(400, gin.H{"error": "use NewToggleRuleHandler"}) }
