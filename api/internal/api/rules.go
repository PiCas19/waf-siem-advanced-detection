package api

import (
	"context"
	"fmt"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/service"
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

// NewGetRulesHandler returns default and custom rules
func NewGetRulesHandler(ruleService *service.RuleService) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get default rules
		defaultRules := GetDefaultRules()

		// Get custom rules from service
		ctx := context.Background()
		customRules, err := ruleService.GetAllRules(ctx)
		if err != nil {
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

// NewGetCustomRulesHandler returns only enabled custom rules for WAF
func NewGetCustomRulesHandler(ruleService *service.RuleService) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := context.Background()
		customRules, err := ruleService.GetEnabledRules(ctx)
		if err != nil {
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

// NewCreateRuleHandler creates a new WAF rule
func NewCreateRuleHandler(ruleService *service.RuleService, db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var rule models.Rule
		userID, _ := c.Get("user_id")
		userEmail, _ := c.Get("user_email")
		clientIP, _ := c.Get("client_ip")
		ctx := context.Background()

		if err := c.ShouldBindJSON(&rule); err != nil {
			fmt.Printf("[ERROR] Failed to parse rule: %v\n", err)
			LogAuditActionWithError(db, userID.(uint), userEmail.(string), "CREATE_RULE", "RULE", "rule", "", "Invalid rule data format", nil, clientIP.(string), "Invalid JSON format")
			c.JSON(400, gin.H{"error": "Invalid rule data"})
			return
		}

		if rule.Name == "" || rule.Pattern == "" {
			LogAuditActionWithError(db, userID.(uint), userEmail.(string), "CREATE_RULE", "RULE", "rule", "", "Missing required fields: Name and Pattern", nil, clientIP.(string), "Missing required fields")
			c.JSON(400, gin.H{"error": "Name and Pattern are required"})
			return
		}

		rule.Enabled = true
		rule.CreatedBy = userID.(uint)

		// If rule is in "detect" mode, disable all action types
		if rule.Action == "log" {
			rule.BlockEnabled = false
			rule.DropEnabled = false
			rule.RedirectEnabled = false
			rule.ChallengeEnabled = false
		}

		if err := ruleService.CreateRule(ctx, &rule); err != nil {
			fmt.Printf("[ERROR] Failed to create rule: %v\n", err)
			LogAuditActionWithError(db, userID.(uint), userEmail.(string), "CREATE_RULE", "RULE", "rule", "", "Database error: failed to create rule", nil, clientIP.(string), err.Error())
			c.JSON(500, gin.H{"error": "failed to create rule"})
			return
		}

		details := map[string]interface{}{
			"type":   rule.Type,
			"action": rule.Action,
			"pattern": rule.Pattern,
		}

		LogRuleAction(db, userID.(uint), userEmail.(string), "CREATE_RULE", fmt.Sprintf("%d", rule.ID), rule.Name, details, clientIP.(string))

		fmt.Printf("[INFO] Rule created: ID=%d, Name=%s, Type=%s, Action=%s\n", rule.ID, rule.Name, rule.Type, rule.Action)

		c.JSON(201, gin.H{
			"message": "Rule created successfully",
			"rule":    rule,
		})
	}
}

// NewUpdateRuleHandler updates an existing WAF rule
func NewUpdateRuleHandler(ruleService *service.RuleService, db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		ruleID := c.Param("id")
		id, err := strconv.ParseUint(ruleID, 10, 32)
		userID, _ := c.Get("user_id")
		userEmail, _ := c.Get("user_email")
		clientIP, _ := c.Get("client_ip")
		ctx := context.Background()

		if err != nil {
			LogAuditActionWithError(db, userID.(uint), userEmail.(string), "UPDATE_RULE", "RULE", "rule", ruleID, "Invalid rule ID format", nil, clientIP.(string), "Invalid rule ID")
			c.JSON(400, gin.H{"error": "Invalid rule ID"})
			return
		}

		var updatedRule models.Rule
		if err := c.ShouldBindJSON(&updatedRule); err != nil {
			LogAuditActionWithError(db, userID.(uint), userEmail.(string), "UPDATE_RULE", "RULE", "rule", ruleID, "Invalid request data format", nil, clientIP.(string), "Invalid JSON format")
			c.JSON(400, gin.H{"error": "Invalid rule data"})
			return
		}

		updatedRule.ID = uint(id)

		// If rule is in "detect" mode, disable all action types
		if updatedRule.Action == "log" {
			updatedRule.BlockEnabled = false
			updatedRule.DropEnabled = false
			updatedRule.RedirectEnabled = false
			updatedRule.ChallengeEnabled = false
		}

		if err := ruleService.UpdateRule(ctx, &updatedRule); err != nil {
			LogAuditActionWithError(db, userID.(uint), userEmail.(string), "UPDATE_RULE", "RULE", "rule", ruleID, "Failed to update rule", nil, clientIP.(string), err.Error())
			if err.Error() == "rule not found" {
				c.JSON(404, gin.H{"error": "Rule not found"})
			} else {
				fmt.Printf("[ERROR] Failed to update rule: %v\n", err)
				c.JSON(500, gin.H{"error": "failed to update rule"})
			}
			return
		}

		// Fetch updated rule
		rule, err := ruleService.GetRuleByID(ctx, uint(id))
		if err != nil {
			c.JSON(500, gin.H{"error": "failed to retrieve updated rule"})
			return
		}

		details := map[string]interface{}{
			"type":   rule.Type,
			"action": rule.Action,
			"pattern": rule.Pattern,
		}

		LogRuleAction(db, userID.(uint), userEmail.(string), "UPDATE_RULE", ruleID, rule.Name, details, clientIP.(string))

		fmt.Printf("[INFO] Rule updated: ID=%d, Name=%s\n", rule.ID, rule.Name)

		c.JSON(200, gin.H{
			"message": "Rule updated successfully",
			"rule":    rule,
		})
	}
}

// NewDeleteRuleHandler deletes a WAF rule
func NewDeleteRuleHandler(ruleService *service.RuleService, db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		ruleID := c.Param("id")
		id, err := strconv.ParseUint(ruleID, 10, 32)
		userID, _ := c.Get("user_id")
		userEmail, _ := c.Get("user_email")
		clientIP, _ := c.Get("client_ip")
		ctx := context.Background()

		if err != nil {
			LogAuditActionWithError(db, userID.(uint), userEmail.(string), "DELETE_RULE", "RULE", "rule", ruleID, "Invalid rule ID format", nil, clientIP.(string), "Invalid rule ID")
			c.JSON(400, gin.H{"error": "Invalid rule ID"})
			return
		}

		// Fetch rule details before deletion for audit log
		rule, err := ruleService.GetRuleByID(ctx, uint(id))
		ruleName := "unknown"
		if err == nil && rule != nil {
			ruleName = rule.Name
		}

		if err := ruleService.DeleteRule(ctx, uint(id)); err != nil {
			LogAuditActionWithError(db, userID.(uint), userEmail.(string), "DELETE_RULE", "RULE", "rule", ruleID, "Failed to delete rule", nil, clientIP.(string), err.Error())
			if err.Error() == "rule not found" {
				c.JSON(404, gin.H{"error": "Rule not found"})
			} else {
				fmt.Printf("[ERROR] Failed to delete rule: %v\n", err)
				c.JSON(500, gin.H{"error": "failed to delete rule"})
			}
			return
		}

		LogRuleAction(db, userID.(uint), userEmail.(string), "DELETE_RULE", ruleID, ruleName, nil, clientIP.(string))

		fmt.Printf("[INFO] Rule deleted: ID=%s\n", ruleID)

		c.JSON(200, gin.H{"message": "Rule deleted successfully"})
	}
}

// NewToggleRuleHandler enables/disables a WAF rule
func NewToggleRuleHandler(ruleService *service.RuleService) gin.HandlerFunc {
	return func(c *gin.Context) {
		ruleID := c.Param("id")
		id, err := strconv.ParseUint(ruleID, 10, 32)
		ctx := context.Background()

		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid rule ID"})
			return
		}

		rule, err := ruleService.GetRuleByID(ctx, uint(id))
		if err != nil {
			if err.Error() == "rule not found" {
				c.JSON(404, gin.H{"error": "Rule not found"})
			} else {
				fmt.Printf("[ERROR] Failed to fetch rule: %v\n", err)
				c.JSON(500, gin.H{"error": "failed to fetch rule"})
			}
			return
		}

		// Toggle the enabled state
		enabled := !rule.Enabled
		if err := ruleService.ToggleRuleEnabled(ctx, uint(id), enabled); err != nil {
			fmt.Printf("[ERROR] Failed to toggle rule: %v\n", err)
			c.JSON(500, gin.H{"error": "failed to toggle rule"})
			return
		}

		fmt.Printf("[INFO] Rule toggled: ID=%d, Enabled=%v\n", rule.ID, enabled)

		c.JSON(200, gin.H{
			"message": "Rule toggled successfully",
			"enabled": enabled,
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
