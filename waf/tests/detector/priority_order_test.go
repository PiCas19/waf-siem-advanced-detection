package detector

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PiCas19/waf-siem-advanced-detection/waf/internal/detector"
)

func TestDetectionPriorityOrder(t *testing.T) {
	d := detector.NewDetector()

	// Test 1: DEFAULT rule (PRIORITY 1) dovrebbe vincere su custom rules
	t.Run("Default rule wins over custom block", func(t *testing.T) {
		// Creiamo una custom rule che matcha "test" (azione log)
		customRules := []*detector.CustomRule{
			{
				ID:       1,
				Name:     "Test Custom Rule",
				Pattern:  `test`,
				Type:     "CUSTOM",
				Severity: "MEDIUM",
				Enabled:  true,
				Action:   "log", // Solo log, non block
			},
		}
		
		err := d.UpdateCustomRules(customRules)
		if err != nil {
			t.Fatalf("Failed to update custom rules: %v", err)
		}

		// Richiesta con XSS (default rule) che contiene anche "test"
		req := httptest.NewRequest("GET", "/search?q=<script>alert('test')</script>", nil)
		req.Header.Set("X-Forwarded-For", "192.168.1.1")
		req.RemoteAddr = "192.168.1.1:12345"

		threat := d.Inspect(req)
		
		if threat == nil {
			t.Error("Expected threat from default XSS rule, got nil")
		} else if threat.Type != "XSS" {
			t.Errorf("Expected XSS threat from default rule, got %s", threat.Type)
		} else if !threat.IsDefault {
			t.Error("Expected IsDefault=true for default rule threat")
		}
	})

	// Test 2: CUSTOM rule with action="block" (PRIORITY 2)
	t.Run("Custom block rule detection", func(t *testing.T) {
		customRules := []*detector.CustomRule{
			{
				ID:           2,
				Name:         "Block Bad Word",
				Pattern:      `(?i)badword`,
				Type:         "CUSTOM",
				Severity:     "HIGH",
				Enabled:      true,
				Action:       "block",
				BlockEnabled: true,
			},
		}
		
		err := d.UpdateCustomRules(customRules)
		if err != nil {
			t.Fatalf("Failed to update custom rules: %v", err)
		}

		// Richiesta con "badword" ma senza pattern di default rule
		req := httptest.NewRequest("GET", "/search?q=thisisabadwordtest", nil)
		req.Header.Set("X-Forwarded-For", "192.168.1.1")
		req.RemoteAddr = "192.168.1.1:12345"

		threat := d.Inspect(req)
		
		if threat == nil {
			t.Error("Expected threat from custom block rule, got nil")
		} else if threat.Type != "CUSTOM" {
			t.Errorf("Expected CUSTOM threat, got %s", threat.Type)
		} else if threat.IsDefault {
			t.Error("Expected IsDefault=false for custom rule threat")
		} else if threat.Action != "block" {
			t.Errorf("Expected Action=block, got %s", threat.Action)
		}
	})

	// Test 3: MANUAL BLOCK rule (PRIORITY 3)
	t.Run("Manual block rule detection", func(t *testing.T) {
		customRules := []*detector.CustomRule{
			{
				ID:           3,
				Name:         "Manual Block IP",
				Pattern:      `manualblock`,
				Type:         "MANUAL_BLOCK",
				Severity:     "CRITICAL",
				Enabled:      true,
				Action:       "block",
				BlockEnabled: true,
				IsManualBlock: true,
			},
		}
		
		err := d.UpdateCustomRules(customRules)
		if err != nil {
			t.Fatalf("Failed to update custom rules: %v", err)
		}

		// Richiesta con "manualblock" pattern
		req := httptest.NewRequest("GET", "/search?q=manualblocktest", nil)
		req.Header.Set("X-Forwarded-For", "192.168.1.1")
		req.RemoteAddr = "192.168.1.1:12345"

		threat := d.Inspect(req)
		
		if threat == nil {
			t.Error("Expected threat from manual block rule, got nil")
		} else if threat.Type != "MANUAL_BLOCK" {
			t.Errorf("Expected MANUAL_BLOCK threat, got %s", threat.Type)
		} else if !strings.Contains(threat.Description, "Manual Block") {
			t.Errorf("Expected description containing 'Manual Block', got %s", threat.Description)
		}
	})

	// Test 4: DETECTED rule with action="log" (PRIORITY 4)
	t.Run("Detect-only rule (log action)", func(t *testing.T) {
		customRules := []*detector.CustomRule{
			{
				ID:           4,
				Name:         "Detect Sensitive Info",
				Pattern:      `(?i)ssn.*\d{3}-\d{2}-\d{4}`,
				Type:         "CUSTOM",
				Severity:     "MEDIUM",
				Enabled:      true,
				Action:       "log", // Solo detection, no blocking
				BlockEnabled: false,
			},
		}
		
		err := d.UpdateCustomRules(customRules)
		if err != nil {
			t.Fatalf("Failed to update custom rules: %v", err)
		}

		// Richiesta con SSN pattern ma senza altre minacce
		req := httptest.NewRequest("POST", "/form", strings.NewReader("ssn=123-45-6789"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Forwarded-For", "192.168.1.1")
		req.RemoteAddr = "192.168.1.1:12345"

		threat := d.Inspect(req)
		
		if threat == nil {
			t.Error("Expected threat from detect-only rule, got nil")
		} else if threat.Type != "CUSTOM" {
			t.Errorf("Expected CUSTOM threat, got %s", threat.Type)
		} else if threat.Action != "log" {
			t.Errorf("Expected Action=log, got %s", threat.Action)
		}
	})

	// Test 5: Priorità nell'ordine corretto
	t.Run("Priority order: Default > Custom Block > Manual Block > Detect-only", func(t *testing.T) {
		// Creiamo regole di tutti i tipi che matchano lo stesso input
		customRules := []*detector.CustomRule{
			// Detect-only rule (lowest priority)
			{
				ID:           10,
				Name:         "Detect Test",
				Pattern:      `testpattern`,
				Type:         "CUSTOM",
				Severity:     "LOW",
				Enabled:      true,
				Action:       "log",
				BlockEnabled: false,
			},
			// Manual block rule (higher priority)
			{
				ID:           11,
				Name:         "Manual Block Test",
				Pattern:      `testpattern`,
				Type:         "MANUAL_BLOCK",
				Severity:     "HIGH",
				Enabled:      true,
				Action:       "block",
				BlockEnabled: true,
				IsManualBlock: true,
			},
			// Custom block rule (even higher priority)
			{
				ID:           12,
				Name:         "Custom Block Test",
				Pattern:      `testpattern`,
				Type:         "CUSTOM",
				Severity:     "MEDIUM",
				Enabled:      true,
				Action:       "block",
				BlockEnabled: true,
			},
		}
		
		err := d.UpdateCustomRules(customRules)
		if err != nil {
			t.Fatalf("Failed to update custom rules: %v", err)
		}

		// Input che matcha tutte le regole custom MA è anche un XSS (default rule)
		req := httptest.NewRequest("GET", "/search?q=<script>testpattern</script>", nil)
		req.Header.Set("X-Forwarded-For", "192.168.1.1")
		req.RemoteAddr = "192.168.1.1:12345"

		threat := d.Inspect(req)
		
		// Dovrebbe matchare la default rule (XSS) che ha priorità più alta
		if threat == nil {
			t.Error("Expected threat, got nil")
		} else if threat.Type != "XSS" {
			t.Errorf("Expected XSS (default rule) to win, got %s", threat.Type)
		}
	})

	// Test 6: Disabled rules should not match
	t.Run("Disabled custom rules don't match", func(t *testing.T) {
		customRules := []*detector.CustomRule{
			{
				ID:       20,
				Name:     "Disabled Rule",
				Pattern:  `disabledpattern`,
				Type:     "CUSTOM",
				Severity: "HIGH",
				Enabled:  false, // Disabilitata!
				Action:   "block",
			},
		}
		
		err := d.UpdateCustomRules(customRules)
		if err != nil {
			t.Fatalf("Failed to update custom rules: %v", err)
		}

		req := httptest.NewRequest("GET", "/search?q=disabledpattern", nil)
		req.Header.Set("X-Forwarded-For", "192.168.1.1")
		req.RemoteAddr = "192.168.1.1:12345"

		threat := d.Inspect(req)
		
		// Non dovrebbe esserci threat perché la regola è disabilitata
		if threat != nil {
			t.Errorf("Expected no threat for disabled rule, got %s", threat.Type)
		}
	})
}