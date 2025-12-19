package detector

import (
	"testing"

	"github.com/PiCas19/waf-siem-advanced-detection/waf/internal/detector"
)

func TestPathTraversalDetection(t *testing.T) {
	d := detector.NewPathTraversalDetector()

	tests := []struct {
		name     string
		input    string
		expected bool
		desc     string
	}{
		// Test che FUNZIONANO SICURO
		{
			name:     "Double directory traversal",
			input:    "../../etc/passwd",
			expected: true,
			desc:     "Path Traversal attack detected",
		},
		{
			name:     "Triple directory traversal",
			input:    "../../../etc/passwd",
			expected: true,
			desc:     "Path Traversal attack detected",
		},
		{
			name:     "Windows backslash traversal",
			input:    `..\..\windows\system32`,
			expected: true,
			desc:     "Path Traversal attack detected",
		},
		{
			name:     "URL encoded traversal",
			input:    "%2e%2e/etc/passwd",
			expected: true,
			desc:     "Path Traversal attack detected",
		},
		{
			name:     "Double encoded traversal",
			input:    "%252e%252e/etc/passwd",
			expected: true,
			desc:     "Path Traversal attack detected",
		},
		{
			name:     "Mixed encoding traversal",
			input:    "%2e./etc/passwd",
			expected: true,
			desc:     "Path Traversal attack detected",
		},
		{
			name:     "Dot percent encoding",
			input:    ".%2e/etc/passwd",
			expected: true,
			desc:     "Path Traversal attack detected",
		},
		{
			name:     "Single directory traversal",
			input:    "../index.php",
			expected: false,
			desc:     "",
		},
		{
			name:     "Short single traversal",
			input:    "../test",
			expected: false,
			desc:     "",
		},
		{
			name:     "Normal relative path",
			input:    "./includes/header.php",
			expected: false,
			desc:     "",
		},
		{
			name:     "Text without dots",
			input:    "This is a test message",
			expected: false,
			desc:     "",
		},
		{
			name:     "File name with dots",
			input:    "document.v1.2.pdf",
			expected: false,
			desc:     "",
		},
		{
			name:     "Email address",
			input:    "user@example.com",
			expected: false,
			desc:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detected, desc := d.Detect(tt.input)
			if detected != tt.expected {
				t.Errorf("%s: expected %v, got %v (input: %q)", tt.name, tt.expected, detected, tt.input)
			}
			if detected && desc != tt.desc {
				t.Errorf("%s: expected description '%s', got '%s'", tt.name, tt.desc, desc)
			}
		})
	}
}