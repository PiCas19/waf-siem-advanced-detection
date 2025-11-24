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

		// Ensure severity has a default value
		if rule.Severity == "" {
			rule.Severity = "medium"
		}

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
			"type":     rule.Type,
			"severity": rule.Severity,
			"action":   rule.Action,
			"pattern":  rule.Pattern,
		}

		LogRuleAction(db, userID.(uint), userEmail.(string), "CREATE_RULE", fmt.Sprintf("%d", rule.ID), rule.Name, details, clientIP.(string))

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

		// Fetch existing rule first to preserve immutable fields
		existingRule, err := ruleService.GetRuleByID(ctx, uint(id))
		if err != nil {
			LogAuditActionWithError(db, userID.(uint), userEmail.(string), "UPDATE_RULE", "RULE", "rule", ruleID, "Rule not found", nil, clientIP.(string), err.Error())
			if err.Error() == "rule not found" {
				c.JSON(404, gin.H{"error": "Rule not found"})
			} else {
				c.JSON(500, gin.H{"error": "failed to retrieve rule"})
			}
			return
		}

		// Check if this is a manual block rule - cannot be edited
		if existingRule.IsManualBlock {
			LogAuditActionWithError(db, userID.(uint), userEmail.(string), "UPDATE_RULE", "RULE", "rule", ruleID, "Cannot edit manual block rule", nil, clientIP.(string), "Manual block rules cannot be edited")
			c.JSON(403, gin.H{"error": "Manual block rules cannot be edited. Delete and recreate if needed."})
			return
		}

		// Bind only the mutable fields from the request (without ID as it's from URI)
		var updateRequest struct {
			Name              string `json:"name"`
			Pattern           string `json:"pattern"`
			Description       string `json:"description"`
			Action            string `json:"action"`
			Enabled           bool   `json:"enabled"`
			BlockEnabled      bool   `json:"block_enabled"`
			DropEnabled       bool   `json:"drop_enabled"`
			RedirectEnabled   bool   `json:"redirect_enabled"`
			ChallengeEnabled  bool   `json:"challenge_enabled"`
		}
		if err := c.ShouldBindJSON(&updateRequest); err != nil {
			LogAuditActionWithError(db, userID.(uint), userEmail.(string), "UPDATE_RULE", "RULE", "rule", ruleID, "Invalid request data format", nil, clientIP.(string), "Invalid JSON format")
			c.JSON(400, gin.H{"error": "Invalid rule data"})
			return
		}

		// Build update map with only provided fields
		updates := make(map[string]interface{})

		if updateRequest.Name != "" {
			updates["name"] = updateRequest.Name
			existingRule.Name = updateRequest.Name
		}
		if updateRequest.Pattern != "" {
			updates["pattern"] = updateRequest.Pattern
			existingRule.Pattern = updateRequest.Pattern
		}
		if updateRequest.Description != "" {
			updates["description"] = updateRequest.Description
			existingRule.Description = updateRequest.Description
		}
		if updateRequest.Action != "" {
			updates["action"] = updateRequest.Action
			existingRule.Action = updateRequest.Action
		}

		// Always include boolean fields as they can be toggled
		updates["enabled"] = updateRequest.Enabled
		updates["block_enabled"] = updateRequest.BlockEnabled
		updates["drop_enabled"] = updateRequest.DropEnabled
		updates["redirect_enabled"] = updateRequest.RedirectEnabled
		updates["challenge_enabled"] = updateRequest.ChallengeEnabled

		existingRule.Enabled = updateRequest.Enabled
		existingRule.BlockEnabled = updateRequest.BlockEnabled
		existingRule.DropEnabled = updateRequest.DropEnabled
		existingRule.RedirectEnabled = updateRequest.RedirectEnabled
		existingRule.ChallengeEnabled = updateRequest.ChallengeEnabled

		// If rule is in "detect" mode, disable all action types
		if updateRequest.Action == "log" {
			updates["block_enabled"] = false
			updates["drop_enabled"] = false
			updates["redirect_enabled"] = false
			updates["challenge_enabled"] = false

			existingRule.BlockEnabled = false
			existingRule.DropEnabled = false
			existingRule.RedirectEnabled = false
			existingRule.ChallengeEnabled = false
		}

		// Update only specified fields in database
		if err := db.WithContext(ctx).Model(&models.Rule{}).Where("id = ?", uint(id)).Updates(updates).Error; err != nil {
			LogAuditActionWithError(db, userID.(uint), userEmail.(string), "UPDATE_RULE", "RULE", "rule", ruleID, "Failed to update rule", nil, clientIP.(string), err.Error())
			fmt.Printf("[ERROR] Failed to update rule: %v\n", err)
			c.JSON(500, gin.H{"error": "failed to update rule"})
			return
		}

		// Fetch updated rule to ensure all fields are correct
		rule, err := ruleService.GetRuleByID(ctx, uint(id))
		if err != nil {
			c.JSON(500, gin.H{"error": "failed to retrieve updated rule"})
			return
		}

		details := map[string]interface{}{
			"type":     rule.Type,
			"severity": rule.Severity,
			"action":   rule.Action,
			"pattern":  rule.Pattern,
		}

		LogRuleAction(db, userID.(uint), userEmail.(string), "UPDATE_RULE", ruleID, rule.Name, details, clientIP.(string))

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

		// If this is a manual block rule, revert the threat back to "detected" status
		if rule != nil && rule.IsManualBlock {
			// Extract threat description from rule name: "Manual Block: {description}"
			threatDescription := ""
			if rule.Name != "" && len(rule.Name) > len("Manual Block: ") {
				threatDescription = rule.Name[len("Manual Block: "):]
			}

			// Update logs that match ALL three criteria:
			// 1. Same threat description (from rule name or threat_type)
			// 2. Same payload (from rule pattern)
			// 3. Currently blocked manually (blocked=true AND blocked_by="manual")
			updates := map[string]interface{}{
				"blocked":    false,
				"blocked_by": "",
			}

			if err := db.WithContext(ctx).
				Model(&models.Log{}).
				Where("(threat_type = ? OR description = ?) AND payload = ? AND blocked = ? AND blocked_by = ?",
					threatDescription, threatDescription, rule.Pattern, true, "manual").
				Updates(updates).Error; err != nil {
				fmt.Printf("[ERROR] Failed to revert threat status: %v\n", err)
			}

			// Log the unblock action to WAF log files
			logUnblockToWAF("", threatDescription, rule.Severity, "", "", "")
		}

		LogRuleAction(db, userID.(uint), userEmail.(string), "DELETE_RULE", ruleID, ruleName, nil, clientIP.(string))

		c.JSON(200, gin.H{
			"message": "Rule deleted successfully",
			"manual_block_deleted": rule != nil && rule.IsManualBlock,
		})
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
