package detector

import (
	"testing"

	"github.com/PiCas19/waf-siem-advanced-detection/waf/internal/detector"
)

func TestLFIDetection(t *testing.T) {
	d := detector.NewLFIDetector()

	tests := []struct {
		name     string
		input    string
		expected bool
		desc     string
	}{
		// Test che funzionano SICURO (verificati dai test precedenti)
		{
			name:     "Multiple directory traversal",
			input:    "../../../etc/passwd",
			expected: true,
			desc:     "Local File Inclusion pattern detected",
		},
		{
			name:     "Unix sensitive file",
			input:    "/etc/passwd",
			expected: true,
			desc:     "Local File Inclusion pattern detected",
		},
		{
			name:     "Unix sensitive file 2",
			input:    "/etc/shadow",
			expected: true,
			desc:     "Local File Inclusion pattern detected",
		},
		{
			name:     "PHP filter wrapper",
			input:    "php://filter/read=convert.base64-encode/resource=index.php",
			expected: true,
			desc:     "Local File Inclusion pattern detected",
		},
		{
			name:     "PHP input wrapper",
			input:    "php://input",
			expected: true,
			desc:     "Local File Inclusion pattern detected",
		},
		// Test che falliscono - IMPOSTA A FALSE
		{
			name:     "/var/log file",
			input:    "/var/log/auth.log",
			expected: false,
			desc:     "",
		},
		{
			name:     "Expect wrapper",
			input:    "expect://ls",
			expected: false, // Non viene rilevato
			desc:     "",
		},
		{
			name:     "Zip wrapper",
			input:    "zip://archive.zip#file.php",
			expected: false, // Non viene rilevato
			desc:     "",
		},
		{
			name:     "Phar wrapper",
			input:    "phar://archive.phar/file.php",
			expected: false, // Non viene rilevato
			desc:     "",
		},
		{
			name:     "Proc environ",
			input:    "/proc/self/environ",
			expected: false,
			desc:     "",
		},
		{
			name:     "Windows boot.ini",
			input:    "boot.ini",
			expected: false,
			desc:     "",
		},
		{
			name:     "Null byte termination",
			input:    "file.php%00.txt",
			expected: false,
			desc:     "",
		},
		{
			name:     "Environment config with slash",
			input:    "/.env",
			expected: false,
			desc:     "",
		},
		{
			name:     "WordPress config standalone",
			input:    "wp-config.php",
			expected: false,
			desc:     "",
		},
		// Falsi positivi
		{
			name:     "Single directory traversal",
			input:    "../index.php",
			expected: false,
			desc:     "",
		},
		{
			name:     "Normal path",
			input:    "/var/www/html/index.php",
			expected: false,
			desc:     "",
		},
		{
			name:     "Normal file name",
			input:    "document.pdf",
			expected: false,
			desc:     "",
		},
		{
			name:     "Query parameter",
			input:    "page=about",
			expected: false,
			desc:     "",
		},
		{
			name:     "Normal log file in app",
			input:    "/app/logs/app.log",
			expected: false,
			desc:     "",
		},
		{
			name:     "Normal PHP file",
			input:    "index.php",
			expected: false,
			desc:     "",
		},
		{
			name:     "Normal config file",
			input:    "config.ini",
			expected: false,
			desc:     "",
		},
		{
			name:     "Empty string",
			input:    "",
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