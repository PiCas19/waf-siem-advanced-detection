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

// CreateRule - Crea una nuova regola WAF nel database
func NewCreateRuleHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var rule models.Rule
		if err := c.ShouldBindJSON(&rule); err != nil {
			fmt.Printf("[ERROR] Failed to parse rule: %v\n", err)
			c.JSON(400, gin.H{"error": "Invalid rule data"})
			return
		}

		if rule.Name == "" || rule.Pattern == "" {
			c.JSON(400, gin.H{"error": "Name and Pattern are required"})
			return
		}

		rule.Enabled = true
		if err := db.Create(&rule).Error; err != nil {
			fmt.Printf("[ERROR] Failed to create rule: %v\n", err)
			c.JSON(500, gin.H{"error": "failed to create rule"})
			return
		}

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
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid rule ID"})
			return
		}

		var updatedRule models.Rule
		if err := c.ShouldBindJSON(&updatedRule); err != nil {
			c.JSON(400, gin.H{"error": "Invalid rule data"})
			return
		}

		// Update the rule
		if err := db.Model(&models.Rule{}).Where("id = ?", uint(id)).Updates(updatedRule).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				c.JSON(404, gin.H{"error": "Rule not found"})
			} else {
				fmt.Printf("[ERROR] Failed to update rule: %v\n", err)
				c.JSON(500, gin.H{"error": "failed to update rule"})
			}
			return
		}

		// Fetch the updated rule
		var rule models.Rule
		db.First(&rule, uint(id))

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
		if err != nil {
			c.JSON(400, gin.H{"error": "Invalid rule ID"})
			return
		}

		if err := db.Delete(&models.Rule{}, uint(id)).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				c.JSON(404, gin.H{"error": "Rule not found"})
			} else {
				fmt.Printf("[ERROR] Failed to delete rule: %v\n", err)
				c.JSON(500, gin.H{"error": "failed to delete rule"})
			}
			return
		}

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
