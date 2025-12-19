package logger

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/waf/internal/logger"
)

func TestNewLogger(t *testing.T) {
	// Test case 1: Create logger with valid path
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "test.log")

	l, err := logger.NewLogger(logFile)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer l.Close()

	// Verify file was created
	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		t.Error("Log file was not created")
	}

	// Test case 2: Create directory if it doesn't exist
	nestedDir := filepath.Join(tempDir, "nested", "dir")
	nestedFile := filepath.Join(nestedDir, "test.log")

	l2, err := logger.NewLogger(nestedFile)
	if err != nil {
		t.Fatalf("Failed to create logger with nested directory: %v", err)
	}
	defer l2.Close()

	if _, err := os.Stat(nestedFile); os.IsNotExist(err) {
		t.Error("Nested log file was not created")
	}

	// Test case 3: Invalid path (should fail)
	invalidPath := "/root/nopermission/test.log"
	_, err = logger.NewLogger(invalidPath)
	if err == nil {
		t.Error("Expected error for invalid path, got none")
	}
}

func TestLogger_Log(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "test.log")

	l, err := logger.NewLogger(logFile)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer l.Close()

	// Test case 1: Log entry without timestamp
	entry := logger.LogEntry{
		ThreatType:        "SQLi",
		Severity:          "HIGH",
		Description:       "SQL injection attempt",
		ClientIP:          "192.168.1.100",
		ClientIPSource:    "x-forwarded-for",
		ClientIPTrusted:   true,
		ClientIPVPNReport: false,
		Method:            "POST",
		URL:               "/api/login",
		UserAgent:         "TestAgent",
		Payload:           "SELECT * FROM users",
		Blocked:           true,
		BlockedBy:         "auto",
	}

	err = l.Log(entry)
	if err != nil {
		t.Fatalf("Failed to log entry: %v", err)
	}

	// Verify log file content
	content, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	var loggedEntry logger.LogEntry
	err = json.Unmarshal(content[:len(content)-1], &loggedEntry) // Remove newline
	if err != nil {
		t.Fatalf("Failed to unmarshal log entry: %v", err)
	}

	if loggedEntry.ThreatType != entry.ThreatType {
		t.Errorf("ThreatType mismatch: got %s, want %s", loggedEntry.ThreatType, entry.ThreatType)
	}

	if loggedEntry.Timestamp.IsZero() {
		t.Error("Timestamp should have been set automatically")
	}

	// Test case 2: Log entry with existing timestamp
	now := time.Now()
	entry2 := logger.LogEntry{
		Timestamp:  now,
		ThreatType: "XSS",
		Severity:   "MEDIUM",
	}

	err = l.Log(entry2)
	if err != nil {
		t.Fatalf("Failed to log second entry: %v", err)
	}

	// Verify multiple entries
	content, err = os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	lines := 0
	for _, b := range content {
		if b == '\n' {
			lines++
		}
	}

	if lines != 2 {
		t.Errorf("Expected 2 log entries, got %d", lines)
	}

	// Test case 3: Concurrent logging
	concurrency := 10
	errors := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		go func(id int) {
			entry := logger.LogEntry{
				ThreatType:  "TEST",
				Severity:    "LOW",
				Description: "Concurrent test",
				Payload:     string(rune(id)),
			}
			errors <- l.Log(entry)
		}(i)
	}

	for i := 0; i < concurrency; i++ {
		if err := <-errors; err != nil {
			t.Errorf("Concurrent log failed: %v", err)
		}
	}

	// Verify all entries were written
	content, err = os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	lines = 0
	for _, b := range content {
		if b == '\n' {
			lines++
		}
	}

	expectedEntries := 12 // 2 from previous tests + 10 concurrent
	if lines != expectedEntries {
		t.Errorf("Expected %d log entries after concurrent writes, got %d", expectedEntries, lines)
	}
}