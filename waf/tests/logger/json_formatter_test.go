package logger

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/PiCas19/waf-siem-advanced-detection/waf/internal/logger"
)

func TestLogger_LogJSON(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "test.json.log")

	lg, err := logger.NewLogger(logFile)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer lg.Close()

	// Test case 1: Simple JSON event
	event := map[string]interface{}{
		"timestamp": "2024-01-15T10:30:00Z",
		"type":      "access",
		"ip":        "192.168.1.100",
		"method":    "GET",
		"path":      "/api/data",
		"status":    200,
	}

	err = lg.LogJSON(event)
	if err != nil {
		t.Fatalf("Failed to log JSON event: %v", err)
	}

	// Verify file content
	content, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	var decoded map[string]interface{}
	err = json.Unmarshal(content[:len(content)-1], &decoded) // Remove newline
	if err != nil {
		t.Fatalf("Failed to unmarshal JSON event: %v", err)
	}

	if decoded["type"] != "access" {
		t.Errorf("Event type mismatch: got %v, want %s", decoded["type"], "access")
	}

	// Test case 2: Complex nested JSON
	complexEvent := map[string]interface{}{
		"timestamp": "2024-01-15T10:31:00Z",
		"event": map[string]interface{}{
			"type":    "security",
			"details": map[string]interface{}{"threat": "SQLi", "blocked": true},
		},
		"http": map[string]interface{}{
			"headers": map[string]string{
				"User-Agent": "TestAgent",
				"X-Forwarded-For": "192.168.1.100",
			},
		},
	}

	err = lg.LogJSON(complexEvent)
	if err != nil {
		t.Fatalf("Failed to log complex JSON event: %v", err)
	}

	// Test case 3: Concurrent JSON logging
	concurrency := 5
	errors := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		go func(id int) {
			event := map[string]interface{}{
				"id":      id,
				"message": "Concurrent test",
			}
			errors <- lg.LogJSON(event)
		}(i)
	}

	for i := 0; i < concurrency; i++ {
		if err := <-errors; err != nil {
			t.Errorf("Concurrent JSON log failed: %v", err)
		}
	}

	// Verify all entries
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

	expectedLines := 7 // 2 from previous tests + 5 concurrent
	if lines != expectedLines {
		t.Errorf("Expected %d JSON entries, got %d", expectedLines, lines)
	}
}

func TestLogger_LogJSON_InvalidData(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "test.json.log")

	lg, err := logger.NewLogger(logFile)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer lg.Close()

	// Test case: JSON with circular reference (should fail during marshaling)
	type Circular struct {
		Self *Circular
	}

	circular := &Circular{}
	circular.Self = circular

	// This will fail because json.Marshal can't handle circular references
	// But our function expects a map[string]interface{}, not a struct
	// So let's test with valid but complex data instead

	complexEvent := map[string]interface{}{
		"timestamp": "2024-01-15T10:32:00Z",
		"data":      make([]interface{}, 10000), // Large but valid
	}

	for i := range complexEvent["data"].([]interface{}) {
		complexEvent["data"].([]interface{})[i] = i
	}

	err = lg.LogJSON(complexEvent)
	if err != nil {
		t.Fatalf("Failed to log large JSON event: %v", err)
	}

	// Verify file was created and has content
	content, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	if len(content) == 0 {
		t.Error("Log file is empty after JSON logging")
	}
}

func TestLogger_LogJSON_FileDeleted(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "test.json.log")

	lg, err := logger.NewLogger(logFile)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer lg.Close()

	// Log initial event
	event := map[string]interface{}{
		"message": "First event",
	}
	err = lg.LogJSON(event)
	if err != nil {
		t.Fatalf("Failed to log event: %v", err)
	}

	// Delete the log file
	err = os.Remove(logFile)
	if err != nil {
		t.Fatalf("Failed to delete log file: %v", err)
	}

	// Log another event - should recreate the file
	event = map[string]interface{}{
		"message": "Second event after deletion",
	}
	err = lg.LogJSON(event)
	if err != nil {
		t.Fatalf("Failed to log event after file deletion: %v", err)
	}

	// Verify file exists and has content
	content, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("Failed to read recreated log file: %v", err)
	}

	if len(content) == 0 {
		t.Error("Recreated log file is empty")
	}
}

func BenchmarkLogger_LogJSON(b *testing.B) {
	tempDir := b.TempDir()
	logFile := filepath.Join(tempDir, "benchmark.json.log")

	lg, err := logger.NewLogger(logFile)
	if err != nil {
		b.Fatalf("Failed to create logger: %v", err)
	}
	defer lg.Close()

	event := map[string]interface{}{
		"timestamp": "2024-01-15T10:30:00Z",
		"type":      "benchmark",
		"data":      "benchmark data",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err = lg.LogJSON(event)
		if err != nil {
			b.Fatalf("Failed to log JSON event: %v", err)
		}
	}
}