package logger

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/waf/internal/logger"
)

func TestLogger_LogBlockedIPEvent(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "events.log")

	lg, err := logger.NewLogger(logFile)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer lg.Close()

	// Test case 1: Event without timestamp
	event := logger.BlockedIPEvent{
		IP:           "192.168.1.100",
		ThreatType:   "SQLi",
		Severity:     "HIGH",
		Description:  "SQL injection attempt",
		Reason:       "Manual block due to repeated attacks",
		Duration:     "permanent",
		Operator:     "admin@example.com",
		OperatorIP:   "10.0.0.1",
		Status:       "success",
	}

	err = lg.LogBlockedIPEvent(event)
	if err != nil {
		t.Fatalf("Failed to log blocked IP event: %v", err)
	}

	// Verify file content
	content, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	var loggedEvent logger.BlockedIPEvent
	err = json.Unmarshal(content[:len(content)-1], &loggedEvent) // Remove newline
	if err != nil {
		t.Fatalf("Failed to unmarshal blocked IP event: %v", err)
	}

	if loggedEvent.IP != event.IP {
		t.Errorf("IP mismatch: got %s, want %s", loggedEvent.IP, event.IP)
	}

	if loggedEvent.EventType != "ip_blocked_manual" {
		t.Errorf("EventType should be 'ip_blocked_manual', got %s", loggedEvent.EventType)
	}

	if loggedEvent.Timestamp.IsZero() {
		t.Error("Timestamp should have been set automatically")
	}

	// Test case 2: Event with existing timestamp
	now := time.Now()
	event2 := logger.BlockedIPEvent{
		Timestamp:   now,
		EventType:   "ip_blocked_manual",
		IP:          "10.0.0.50",
		ThreatType:  "XSS",
		Severity:    "MEDIUM",
		Reason:      "Cross-site scripting attack",
		Duration:    "24 hours",
		Operator:    "security@example.com",
		OperatorIP:  "10.0.0.2",
		Status:      "success",
	}

	err = lg.LogBlockedIPEvent(event2)
	if err != nil {
		t.Fatalf("Failed to log second blocked IP event: %v", err)
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

	// Test case 3: Failed block event
	failedEvent := logger.BlockedIPEvent{
		IP:           "192.168.1.200",
		ThreatType:   "LFI",
		Severity:     "HIGH",
		Reason:       "Local file inclusion attack",
		Duration:     "permanent",
		Operator:     "admin@example.com",
		OperatorIP:   "10.0.0.1",
		Status:       "failed",
	}

	err = lg.LogBlockedIPEvent(failedEvent)
	if err != nil {
		t.Fatalf("Failed to log failed blocked IP event: %v", err)
	}

	// Test case 4: Concurrent event logging
	concurrency := 8
	errors := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		go func(id int) {
			event := logger.BlockedIPEvent{
				IP:         "192.168.1." + string(rune(100+id)),
				ThreatType: "TEST",
				Severity:   "LOW",
				Reason:     "Test concurrent logging",
				Duration:   "temporary",
				Operator:   "test@example.com",
				OperatorIP: "10.0.0.1",
				Status:     "success",
			}
			errors <- lg.LogBlockedIPEvent(event)
		}(i)
	}

	for i := 0; i < concurrency; i++ {
		if err := <-errors; err != nil {
			t.Errorf("Concurrent blocked IP event log failed: %v", err)
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

	expectedEntries := 11 // 3 from previous tests + 8 concurrent
	if lines != expectedEntries {
		t.Errorf("Expected %d log entries after concurrent writes, got %d", expectedEntries, lines)
	}
}

func TestBlockedIPEvent_JSONStructure(t *testing.T) {
	// Verify JSON tags are correct by marshaling
	event := logger.BlockedIPEvent{
		Timestamp:   time.Now(),
		EventType:   "ip_blocked_manual",
		IP:          "192.168.1.100",
		ThreatType:  "SQLi",
		Severity:    "HIGH",
		Description: "SQL injection attempt",
		Reason:      "Manual block",
		Duration:    "permanent",
		Operator:    "admin@example.com",
		OperatorIP:  "10.0.0.1",
		Status:      "success",
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Failed to marshal BlockedIPEvent: %v", err)
	}

	var decoded map[string]interface{}
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	// Check required fields
	requiredFields := []string{
		"timestamp", "event_type", "ip", "threat_type", "severity",
		"description", "reason", "duration", "operator", "operator_ip", "status",
	}

	for _, field := range requiredFields {
		if _, exists := decoded[field]; !exists {
			t.Errorf("Missing required field in JSON: %s", field)
		}
	}

	// Verify specific values
	if decoded["event_type"] != "ip_blocked_manual" {
		t.Errorf("event_type should be 'ip_blocked_manual', got %v", decoded["event_type"])
	}
}

func TestLogger_LogBlockedIPEvent_FileDeleted(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "events.log")

	lg, err := logger.NewLogger(logFile)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer lg.Close()

	// Log initial event
	event := logger.BlockedIPEvent{
		IP:      "192.168.1.100",
		Reason:  "Test",
		Status:  "success",
	}
	err = lg.LogBlockedIPEvent(event)
	if err != nil {
		t.Fatalf("Failed to log event: %v", err)
	}

	// Delete the log file
	err = os.Remove(logFile)
	if err != nil {
		t.Fatalf("Failed to delete log file: %v", err)
	}

	// Log another event - should recreate the file
	event = logger.BlockedIPEvent{
		IP:      "192.168.1.200",
		Reason:  "Test after deletion",
		Status:  "success",
	}
	err = lg.LogBlockedIPEvent(event)
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

func TestBlockedIPEvent_DefaultEventType(t *testing.T) {
	tempDir := t.TempDir()
	logFile := filepath.Join(tempDir, "events.log")

	lg, err := logger.NewLogger(logFile)
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer lg.Close()

	// Test case: Event without EventType (should be set to default)
	event := logger.BlockedIPEvent{
		IP:     "192.168.1.100",
		Reason: "Test",
		Status: "success",
	}

	err = lg.LogBlockedIPEvent(event)
	if err != nil {
		t.Fatalf("Failed to log event: %v", err)
	}

	// Verify file content
	content, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	var loggedEvent logger.BlockedIPEvent
	err = json.Unmarshal(content[:len(content)-1], &loggedEvent)
	if err != nil {
		t.Fatalf("Failed to unmarshal event: %v", err)
	}

	if loggedEvent.EventType != "ip_blocked_manual" {
		t.Errorf("Default EventType should be 'ip_blocked_manual', got %s", loggedEvent.EventType)
	}
}

func BenchmarkLogger_LogBlockedIPEvent(b *testing.B) {
	tempDir := b.TempDir()
	logFile := filepath.Join(tempDir, "benchmark_events.log")

	lg, err := logger.NewLogger(logFile)
	if err != nil {
		b.Fatalf("Failed to create logger: %v", err)
	}
	defer lg.Close()

	event := logger.BlockedIPEvent{
		IP:         "192.168.1.100",
		ThreatType: "TEST",
		Severity:   "LOW",
		Reason:     "Benchmark test",
		Duration:   "temporary",
		Operator:   "benchmark@example.com",
		OperatorIP: "10.0.0.1",
		Status:     "success",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err = lg.LogBlockedIPEvent(event)
		if err != nil {
			b.Fatalf("Failed to log blocked IP event: %v", err)
		}
	}
}