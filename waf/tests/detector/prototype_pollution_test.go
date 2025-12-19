package detector

import (
	"testing"

	"github.com/PiCas19/waf-siem-advanced-detection/waf/internal/detector"
)

func TestPrototypePollutionDetection(t *testing.T) {
	d := detector.NewPrototypePollutionDetector()

	tests := []struct {
		name     string
		input    string
		expected bool
		desc     string
	}{
		// __proto__ access
		{
			name:     "__proto__ bracket access",
			input:    `obj["__proto__"]["polluted"] = "yes"`,
			expected: true,
			desc:     "Prototype Pollution attack detected",
		},
		{
			name:     "__proto__ dot access",
			input:    `obj.__proto__.polluted = "yes"`,
			expected: true,
			desc:     "Prototype Pollution attack detected",
		},
		{
			name:     "__proto__ single quotes",
			input:    `obj['__proto__'].polluted = "yes"`,
			expected: true,
			desc:     "Prototype Pollution attack detected",
		},
		// constructor.prototype
		{
			name:     "constructor prototype bracket",
			input:    `obj.constructor["prototype"].polluted = "yes"`,
			expected: true,
			desc:     "Prototype Pollution attack detected",
		},
		{
			name:     "constructor prototype dot",
			input:    `obj.constructor.prototype.polluted = "yes"`,
			expected: true,
			desc:     "Prototype Pollution attack detected",
		},
		// In JSON
		{
			name:     "JSON with __proto__",
			input:    `{"__proto__": {"polluted": "yes"}}`,
			expected: true,
			desc:     "Prototype Pollution attack detected",
		},
		{
			name:     "JSON with constructor prototype",
			input:    `{"constructor": {"prototype": {"polluted": "yes"}}}`,
			expected: true,
			desc:     "Prototype Pollution attack detected",
		},
		// Falsi positivi
		{
			name:     "Normal object access",
			input:    `obj.prototype.method()`,
			expected: false,
			desc:     "",
		},
		{
			name:     "Text containing proto",
			input:    "protocol://example.com",
			expected: false,
			desc:     "",
		},
		{
			name:     "Normal JSON",
			input:    `{"name": "test", "value": 123}`,
			expected: false,
			desc:     "",
		},
		{
			name:     "Constructor function",
			input:    "function Constructor() {}",
			expected: false,
			desc:     "",
		},
		{
			name:     "Short input",
			input:    "proto",
			expected: false,
			desc:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detected, desc := d.Detect(tt.input)
			if detected != tt.expected {
				t.Errorf("%s: expected %v, got %v", tt.name, tt.expected, detected)
			}
			if detected && desc != tt.desc {
				t.Errorf("%s: expected description '%s', got '%s'", tt.name, tt.desc, desc)
			}
		})
	}
}