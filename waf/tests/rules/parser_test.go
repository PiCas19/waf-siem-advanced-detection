package rules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PiCas19/waf-siem-advanced-detection/waf/internal/rules"
)

func TestLoadRulesFromFile(t *testing.T) {
	// Create temporary directory
	tempDir := t.TempDir()
	rulesFile := filepath.Join(tempDir, "rules.yaml")

	// Create test rules file
	yamlContent := `- id: rule-001
  name: "SQLi Detection"
  description: "Detects SQL injection"
  severity: "HIGH"
  patterns:
    - "union.*select"
    - "or.*1=1"
  enabled: true
  actions:
    - "block"
    - "log"

- id: rule-002
  name: "XSS Detection"
  description: "Detects XSS attacks"
  severity: "MEDIUM"
  patterns:
    - "<script"
    - "javascript:"
  enabled: true
  actions:
    - "log"
`

	err := os.WriteFile(rulesFile, []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test rules file: %v", err)
	}

	// Load rules
	loadedRules, err := rules.LoadRulesFromFile(rulesFile)
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}

	// Verify number of rules
	if len(loadedRules) != 2 {
		t.Errorf("Expected 2 rules, got %d", len(loadedRules))
	}

	// Verify first rule
	if loadedRules[0].ID != "rule-001" {
		t.Errorf("Expected first rule ID 'rule-001', got %s", loadedRules[0].ID)
	}
	if loadedRules[0].Name != "SQLi Detection" {
		t.Errorf("Expected first rule name 'SQLi Detection', got %s", loadedRules[0].Name)
	}
	if loadedRules[0].Severity != "HIGH" {
		t.Errorf("Expected first rule severity 'HIGH', got %s", loadedRules[0].Severity)
	}
	if !loadedRules[0].Enabled {
		t.Error("Expected first rule to be enabled")
	}
	if len(loadedRules[0].Patterns) != 2 {
		t.Errorf("Expected 2 patterns in first rule, got %d", len(loadedRules[0].Patterns))
	}

	// Verify second rule
	if loadedRules[1].ID != "rule-002" {
		t.Errorf("Expected second rule ID 'rule-002', got %s", loadedRules[1].ID)
	}
	if loadedRules[1].Severity != "MEDIUM" {
		t.Errorf("Expected second rule severity 'MEDIUM', got %s", loadedRules[1].Severity)
	}
}

func TestLoadRulesFromFile_FileNotFound(t *testing.T) {
	_, err := rules.LoadRulesFromFile("/nonexistent/path/rules.yaml")
	if err == nil {
		t.Error("Expected error for nonexistent file, got nil")
	}
}

func TestLoadRulesFromFile_InvalidYAML(t *testing.T) {
	tempDir := t.TempDir()
	rulesFile := filepath.Join(tempDir, "invalid.yaml")

	// Create file with truly invalid YAML (unmatched brackets)
	invalidYAML := `- id: rule-001
  name: Invalid Rule [[[
  patterns:
    - pattern1
  enabled: true
  actions: [block, log
`

	err := os.WriteFile(rulesFile, []byte(invalidYAML), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	_, err = rules.LoadRulesFromFile(rulesFile)
	if err == nil {
		t.Error("Expected error for invalid YAML, got nil")
	}
}

func TestLoadRulesFromFile_EmptyFile(t *testing.T) {
	tempDir := t.TempDir()
	rulesFile := filepath.Join(tempDir, "empty.yaml")

	err := os.WriteFile(rulesFile, []byte(""), 0644)
	if err != nil {
		t.Fatalf("Failed to create empty file: %v", err)
	}

	loadedRules, err := rules.LoadRulesFromFile(rulesFile)
	if err != nil {
		t.Fatalf("Failed to load empty rules file: %v", err)
	}

	if len(loadedRules) != 0 {
		t.Errorf("Expected 0 rules from empty file, got %d", len(loadedRules))
	}
}

func TestLoadRulesFromDir(t *testing.T) {
	tempDir := t.TempDir()

	// Create multiple rule files
	rule1 := `- id: dir-rule-001
  name: Rule 1
  severity: HIGH
  patterns:
    - pattern1
  enabled: true
  actions:
    - block
`

	rule2 := `- id: dir-rule-002
  name: Rule 2
  severity: MEDIUM
  patterns:
    - pattern2
  enabled: true
  actions:
    - log

- id: dir-rule-003
  name: Rule 3
  severity: LOW
  patterns:
    - pattern3
  enabled: false
  actions:
    - log
`

	err := os.WriteFile(filepath.Join(tempDir, "rules1.yaml"), []byte(rule1), 0644)
	if err != nil {
		t.Fatalf("Failed to create rules1.yaml: %v", err)
	}

	err = os.WriteFile(filepath.Join(tempDir, "rules2.yaml"), []byte(rule2), 0644)
	if err != nil {
		t.Fatalf("Failed to create rules2.yaml: %v", err)
	}

	// Load rules from directory
	loadedRules, err := rules.LoadRulesFromDir(tempDir)
	if err != nil {
		t.Fatalf("Failed to load rules from directory: %v", err)
	}

	// Should have 3 rules total (1 from file1 + 2 from file2)
	if len(loadedRules) != 3 {
		t.Errorf("Expected 3 rules, got %d", len(loadedRules))
	}

	// Verify we have all rule IDs
	ruleIDs := make(map[string]bool)
	for _, rule := range loadedRules {
		ruleIDs[rule.ID] = true
	}

	expectedIDs := []string{"dir-rule-001", "dir-rule-002", "dir-rule-003"}
	for _, id := range expectedIDs {
		if !ruleIDs[id] {
			t.Errorf("Expected to find rule ID %s", id)
		}
	}
}

func TestLoadRulesFromDir_DirectoryNotFound(t *testing.T) {
	_, err := rules.LoadRulesFromDir("/nonexistent/directory")
	if err == nil {
		t.Error("Expected error for nonexistent directory, got nil")
	}
}

func TestLoadRulesFromDir_EmptyDirectory(t *testing.T) {
	tempDir := t.TempDir()

	loadedRules, err := rules.LoadRulesFromDir(tempDir)
	if err != nil {
		t.Fatalf("Failed to load from empty directory: %v", err)
	}

	if len(loadedRules) != 0 {
		t.Errorf("Expected 0 rules from empty directory, got %d", len(loadedRules))
	}
}

func TestLoadRulesFromDir_WithSubdirectories(t *testing.T) {
	tempDir := t.TempDir()

	// Create a subdirectory
	subDir := filepath.Join(tempDir, "subdir")
	err := os.Mkdir(subDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create subdirectory: %v", err)
	}

	// Create rule file in main directory
	ruleContent := `- id: main-rule
  name: Main Rule
  severity: HIGH
  patterns:
    - pattern1
  enabled: true
  actions:
    - block
`

	err = os.WriteFile(filepath.Join(tempDir, "main.yaml"), []byte(ruleContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create main rule file: %v", err)
	}

	// Create rule file in subdirectory (should be ignored)
	err = os.WriteFile(filepath.Join(subDir, "sub.yaml"), []byte(ruleContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create sub rule file: %v", err)
	}

	// Load rules
	loadedRules, err := rules.LoadRulesFromDir(tempDir)
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}

	// Should only have 1 rule (subdirectory files are ignored)
	if len(loadedRules) != 1 {
		t.Errorf("Expected 1 rule (subdirectories ignored), got %d", len(loadedRules))
	}
}

func TestLoadRulesFromDir_MixedValidInvalid(t *testing.T) {
	tempDir := t.TempDir()

	// Create valid rule file
	validRule := `- id: valid-rule
  name: Valid Rule
  severity: HIGH
  patterns:
    - pattern1
  enabled: true
  actions:
    - block
`

	// Create invalid rule file
	invalidRule := `invalid yaml content [[[`

	err := os.WriteFile(filepath.Join(tempDir, "valid.yaml"), []byte(validRule), 0644)
	if err != nil {
		t.Fatalf("Failed to create valid rule file: %v", err)
	}

	err = os.WriteFile(filepath.Join(tempDir, "invalid.yaml"), []byte(invalidRule), 0644)
	if err != nil {
		t.Fatalf("Failed to create invalid rule file: %v", err)
	}

	// Load rules (should skip invalid files)
	loadedRules, err := rules.LoadRulesFromDir(tempDir)
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}

	// Should have 1 rule (invalid file skipped)
	if len(loadedRules) != 1 {
		t.Errorf("Expected 1 rule (invalid file skipped), got %d", len(loadedRules))
	}

	if loadedRules[0].ID != "valid-rule" {
		t.Errorf("Expected rule ID 'valid-rule', got %s", loadedRules[0].ID)
	}
}

func TestLoadRulesFromDir_NonYAMLFiles(t *testing.T) {
	tempDir := t.TempDir()

	// Create YAML rule file
	yamlRule := `- id: yaml-rule
  name: YAML Rule
  severity: HIGH
  patterns:
    - pattern1
  enabled: true
  actions:
    - block
`

	err := os.WriteFile(filepath.Join(tempDir, "rules.yaml"), []byte(yamlRule), 0644)
	if err != nil {
		t.Fatalf("Failed to create YAML file: %v", err)
	}

	// Create non-YAML files
	err = os.WriteFile(filepath.Join(tempDir, "README.md"), []byte("# README"), 0644)
	if err != nil {
		t.Fatalf("Failed to create README: %v", err)
	}

	err = os.WriteFile(filepath.Join(tempDir, "config.txt"), []byte("config"), 0644)
	if err != nil {
		t.Fatalf("Failed to create txt file: %v", err)
	}

	// Load rules
	loadedRules, err := rules.LoadRulesFromDir(tempDir)
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}

	// Should have 1 rule (non-YAML files are attempted but fail gracefully)
	if len(loadedRules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(loadedRules))
	}
}
