package repository

import (
	"context"
	"testing"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/logger"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/repository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func init() {
	logger.InitLogger("error", "stdout")
}

func setupRuleDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&models.Rule{})
	require.NoError(t, err)

	return db
}

func createTestRule(db *gorm.DB, name, ruleType, pattern string, enabled bool) models.Rule {
	rule := models.Rule{
		Name:        name,
		Type:        ruleType,
		Pattern:     pattern,
		Enabled:     enabled,
		Description: "Test rule",
		Severity:    "high",
	}
	db.Create(&rule)
	// GORM doesn't set boolean false due to default:true, so we need to explicitly update it
	if !enabled {
		db.Model(&rule).Update("enabled", false)
	}
	return rule
}

func TestNewGormRuleRepository(t *testing.T) {
	db := setupRuleDB(t)
	repo := repository.NewGormRuleRepository(db)
	assert.NotNil(t, repo)
}

func TestRuleRepository_FindAll(t *testing.T) {
	db := setupRuleDB(t)
	repo := repository.NewGormRuleRepository(db)
	ctx := context.Background()

	createTestRule(db, "SQL Injection Rule", "sql_injection", "SELECT.*FROM", true)
	createTestRule(db, "XSS Rule", "xss", "<script>", true)
	createTestRule(db, "CSRF Rule", "csrf", "CSRF-Token", false)

	rules, err := repo.FindAll(ctx)
	assert.NoError(t, err)
	assert.Len(t, rules, 3)
}

func TestRuleRepository_FindByID(t *testing.T) {
	db := setupRuleDB(t)
	repo := repository.NewGormRuleRepository(db)
	ctx := context.Background()

	created := createTestRule(db, "Test Rule", "sql_injection", "SELECT", true)

	found, err := repo.FindByID(ctx, created.ID)
	assert.NoError(t, err)
	require.NotNil(t, found)
	assert.Equal(t, created.ID, found.ID)
	assert.Equal(t, "Test Rule", found.Name)
}

func TestRuleRepository_FindByID_NotFound(t *testing.T) {
	db := setupRuleDB(t)
	repo := repository.NewGormRuleRepository(db)
	ctx := context.Background()

	found, err := repo.FindByID(ctx, 9999)
	assert.NoError(t, err)
	assert.Nil(t, found)
}

func TestRuleRepository_FindEnabled(t *testing.T) {
	db := setupRuleDB(t)
	repo := repository.NewGormRuleRepository(db)
	ctx := context.Background()

	createTestRule(db, "Enabled Rule 1", "sql_injection", "SELECT", true)
	createTestRule(db, "Disabled Rule", "xss", "<script>", false)
	createTestRule(db, "Enabled Rule 2", "lfi", "../", true)

	rules, err := repo.FindEnabled(ctx)
	assert.NoError(t, err)
	assert.Len(t, rules, 2)

	for _, rule := range rules {
		assert.True(t, rule.Enabled)
	}
}

func TestRuleRepository_Create(t *testing.T) {
	db := setupRuleDB(t)
	repo := repository.NewGormRuleRepository(db)
	ctx := context.Background()

	rule := &models.Rule{
		Name:        "New Rule",
		Type:        "sql_injection",
		Pattern:     "UNION SELECT",
		Enabled:     true,
		Description: "Detects SQL injection",
		Severity:    "critical",
	}

	err := repo.Create(ctx, rule)
	assert.NoError(t, err)
	assert.NotZero(t, rule.ID)
}

func TestRuleRepository_Update(t *testing.T) {
	db := setupRuleDB(t)
	repo := repository.NewGormRuleRepository(db)
	ctx := context.Background()

	rule := createTestRule(db, "Original Rule", "sql_injection", "SELECT", true)

	rule.Name = "Updated Rule"
	rule.Pattern = "UPDATE"
	rule.Enabled = false

	err := repo.Update(ctx, &rule)
	assert.NoError(t, err)

	updated, err := repo.FindByID(ctx, rule.ID)
	assert.NoError(t, err)
	assert.Equal(t, "Updated Rule", updated.Name)
	assert.Equal(t, "UPDATE", updated.Pattern)
	assert.False(t, updated.Enabled)
}

func TestRuleRepository_Delete(t *testing.T) {
	db := setupRuleDB(t)
	repo := repository.NewGormRuleRepository(db)
	ctx := context.Background()

	rule := createTestRule(db, "Test Rule", "sql_injection", "SELECT", true)

	err := repo.Delete(ctx, rule.ID)
	assert.NoError(t, err)

	found, err := repo.FindByID(ctx, rule.ID)
	assert.NoError(t, err)
	assert.Nil(t, found)
}

func TestRuleRepository_ToggleEnabled(t *testing.T) {
	db := setupRuleDB(t)
	repo := repository.NewGormRuleRepository(db)
	ctx := context.Background()

	rule := createTestRule(db, "Test Rule", "sql_injection", "SELECT", true)

	// Disable the rule
	err := repo.ToggleEnabled(ctx, rule.ID, false)
	assert.NoError(t, err)

	found, err := repo.FindByID(ctx, rule.ID)
	assert.NoError(t, err)
	assert.False(t, found.Enabled)

	// Enable the rule
	err = repo.ToggleEnabled(ctx, rule.ID, true)
	assert.NoError(t, err)

	found, err = repo.FindByID(ctx, rule.ID)
	assert.NoError(t, err)
	assert.True(t, found.Enabled)
}

func TestRuleRepository_Count(t *testing.T) {
	db := setupRuleDB(t)
	repo := repository.NewGormRuleRepository(db)
	ctx := context.Background()

	createTestRule(db, "Rule 1", "sql_injection", "SELECT", true)
	createTestRule(db, "Rule 2", "xss", "<script>", true)
	createTestRule(db, "Rule 3", "lfi", "../", false)

	count, err := repo.Count(ctx)
	assert.NoError(t, err)
	assert.Equal(t, int64(3), count)
}

func TestRuleRepository_FindByType(t *testing.T) {
	db := setupRuleDB(t)
	repo := repository.NewGormRuleRepository(db)
	ctx := context.Background()

	createTestRule(db, "SQL Rule 1", "sql_injection", "SELECT", true)
	createTestRule(db, "SQL Rule 2", "sql_injection", "UNION", true)
	createTestRule(db, "XSS Rule", "xss", "<script>", true)
	createTestRule(db, "Disabled SQL Rule", "sql_injection", "DROP", false)

	rules, err := repo.FindByType(ctx, "sql_injection")
	assert.NoError(t, err)
	assert.Len(t, rules, 2) // Only enabled SQL injection rules

	for _, rule := range rules {
		assert.Equal(t, "sql_injection", rule.Type)
		assert.True(t, rule.Enabled)
	}
}

func TestRuleRepository_FindPaginated(t *testing.T) {
	db := setupRuleDB(t)
	repo := repository.NewGormRuleRepository(db)
	ctx := context.Background()

	// Create 15 rules
	for i := 0; i < 15; i++ {
		createTestRule(db, "Rule", "sql_injection", "SELECT", true)
	}

	// First page
	rules, total, err := repo.FindPaginated(ctx, 0, 10)
	assert.NoError(t, err)
	assert.Len(t, rules, 10)
	assert.Equal(t, int64(15), total)

	// Second page
	rules, total, err = repo.FindPaginated(ctx, 10, 10)
	assert.NoError(t, err)
	assert.Len(t, rules, 5)
	assert.Equal(t, int64(15), total)
}

func TestRuleRepository_FindEnabled_AllDisabled(t *testing.T) {
	db := setupRuleDB(t)
	repo := repository.NewGormRuleRepository(db)
	ctx := context.Background()

	createTestRule(db, "Disabled Rule 1", "sql_injection", "SELECT", false)
	createTestRule(db, "Disabled Rule 2", "xss", "<script>", false)

	rules, err := repo.FindEnabled(ctx)
	assert.NoError(t, err)
	assert.Empty(t, rules)
}

func TestRuleRepository_FindByType_NoResults(t *testing.T) {
	db := setupRuleDB(t)
	repo := repository.NewGormRuleRepository(db)
	ctx := context.Background()

	createTestRule(db, "SQL Rule", "sql_injection", "SELECT", true)

	rules, err := repo.FindByType(ctx, "nonexistent_type")
	assert.NoError(t, err)
	assert.Empty(t, rules)
}

func TestRuleRepository_ToggleEnabled_NonExistent(t *testing.T) {
	db := setupRuleDB(t)
	repo := repository.NewGormRuleRepository(db)
	ctx := context.Background()

	// Should not error, just affect 0 rows
	err := repo.ToggleEnabled(ctx, 9999, true)
	assert.NoError(t, err)
}
