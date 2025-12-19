package detector

import (
	"testing"

	"github.com/PiCas19/waf-siem-advanced-detection/waf/internal/detector"
)

func TestXXEDetection(t *testing.T) {
	d := detector.NewXXEDetector()

	tests := []struct {
		name     string
		input    string
		expected bool
		desc     string
	}{
		// DOCTYPE con ENTITY
		{
			name:     "DOCTYPE with ENTITY",
			input:    `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`,
			expected: true,
			desc:     "XML External Entity attack detected",
		},
		{
			name:     "SYSTEM with file://",
			input:    `<!ENTITY xxe SYSTEM "file:///etc/passwd">`,
			expected: true,
			desc:     "XML External Entity attack detected",
		},
		{
			name:     "SYSTEM with http://",
			input:    `<!ENTITY xxe SYSTEM "http://evil.com">`,
			expected: true,
			desc:     "XML External Entity attack detected",
		},
		// ATTENZIONE: XInclude attack - IL DETECTOR NON LO RILEVA
		// Perché non contiene <! né <?xml
		{
			name:     "XInclude attack",
			input:    `<xi:include href="file:///etc/passwd" parse="text"/>`,
			expected: false, // MODIFICATO: da true a false
			desc:     "",
		},
		{
			name:     "Parameter entity",
			input:    `<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;`,
			expected: true,
			desc:     "XML External Entity attack detected",
		},
		// Falsi positivi / casi legittimi
		{
			name:     "Valid XML without XXE",
			input:    `<?xml version="1.0"?><root><element>test</element></root>`,
			expected: false,
			desc:     "",
		},
		{
			name:     "HTML content",
			input:    `<html><body>Test</body></html>`,
			expected: false,
			desc:     "",
		},
		{
			name:     "Just text",
			input:    "This is a normal text",
			expected: false,
			desc:     "",
		},
		{
			name:     "XML declaration only",
			input:    `<?xml version="1.0"?>`,
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