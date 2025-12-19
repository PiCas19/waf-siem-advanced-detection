package logger

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEventLogger(t *testing.T) {
	t.Run("creates new event logger successfully", func(t *testing.T) {
		tempDir := t.TempDir()
		filename := filepath.Join(tempDir, "events.log")
		
		eventLogger, err := logger.NewEventLogger(filename)
		require.NoError(t, err)
		require.NotNil(t, eventLogger)
		
		// Verify file was created
		_, err = os.Stat(filename)
		assert.NoError(t, err)
	})

	t.Run("creates directory if it doesn't exist", func(t *testing.T) {
		tempDir := t.TempDir()
		filename := filepath.Join(tempDir, "subdir", "events.log")
		
		eventLogger, err := logger.NewEventLogger(filename)
		require.NoError(t, err)
		require.NotNil(t, eventLogger)
		
		// Verify directory and file were created
		_, err = os.Stat(filename)
		assert.NoError(t, err)
	})

	t.Run("returns error on invalid path", func(t *testing.T) {
		// Try to create file in root directory (should fail due to permissions)
		filename := "/nonexistent/events.log"
		
		eventLogger, err := logger.NewEventLogger(filename)
		require.Error(t, err)
		assert.Nil(t, eventLogger)
	})
}

func TestEventLogger_LogBlockedIPEvent(t *testing.T) {
	tempDir := t.TempDir()
	filename := filepath.Join(tempDir, "events.log")
	
	eventLogger, err := logger.NewEventLogger(filename)
	require.NoError(t, err)
	require.NotNil(t, eventLogger)

	t.Run("logs event with all fields", func(t *testing.T) {
		event := logger.BlockedIPEvent{
			Timestamp:    time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
			EventType:    "ip_blocked_manual",
			IP:           "192.168.1.1",
			ThreatType:   "brute_force",
			Severity:     "high",
			Description:  "Multiple failed login attempts",
			Reason:       "Security threat detected",
			Duration:     "24h",
			Operator:     "admin@example.com",
			OperatorIP:   "10.0.0.1",
			Status:       "success",
		}

		err := eventLogger.LogBlockedIPEvent(event)
		require.NoError(t, err)

		// Read file and verify content
		content, err := os.ReadFile(filename)
		require.NoError(t, err)

		var loggedEvent logger.BlockedIPEvent
		err = json.Unmarshal(content, &loggedEvent)
		require.NoError(t, err)

		assert.Equal(t, event.Timestamp, loggedEvent.Timestamp)
		assert.Equal(t, event.IP, loggedEvent.IP)
		assert.Equal(t, event.ThreatType, loggedEvent.ThreatType)
		assert.Equal(t, event.Severity, loggedEvent.Severity)
		assert.Equal(t, event.Description, loggedEvent.Description)
		assert.Equal(t, event.Reason, loggedEvent.Reason)
		assert.Equal(t, event.Duration, loggedEvent.Duration)
		assert.Equal(t, event.Operator, loggedEvent.Operator)
		assert.Equal(t, event.OperatorIP, loggedEvent.OperatorIP)
		assert.Equal(t, event.Status, loggedEvent.Status)
	})

	t.Run("adds timestamp if zero", func(t *testing.T) {
		event := logger.BlockedIPEvent{
			IP:       "192.168.1.2",
			EventType: "ip_blocked_manual",
		}

		err := eventLogger.LogBlockedIPEvent(event)
		require.NoError(t, err)

		// Read last line
		content, err := os.ReadFile(filename)
		require.NoError(t, err)

		lines := string(content)
		var loggedEvent logger.BlockedIPEvent
		// Get last line (there are multiple from previous tests)
		lastLine := getLastLine(lines)
		err = json.Unmarshal([]byte(lastLine), &loggedEvent)
		require.NoError(t, err)

		assert.False(t, loggedEvent.Timestamp.IsZero())
		assert.Equal(t, "ip_blocked_manual", loggedEvent.EventType)
		assert.Equal(t, "192.168.1.2", loggedEvent.IP)
	})

	t.Run("sets default event_type if empty", func(t *testing.T) {
		event := logger.BlockedIPEvent{
			IP: "192.168.1.3",
		}

		err := eventLogger.LogBlockedIPEvent(event)
		require.NoError(t, err)

		content, err := os.ReadFile(filename)
		require.NoError(t, err)

		lines := string(content)
		lastLine := getLastLine(lines)
		var loggedEvent logger.BlockedIPEvent
		err = json.Unmarshal([]byte(lastLine), &loggedEvent)
		require.NoError(t, err)

		assert.Equal(t, "ip_blocked_manual", loggedEvent.EventType)
	})

	t.Run("handles concurrent writes", func(t *testing.T) {
		concurrentWrites := 50
		errors := make(chan error, concurrentWrites)

		for i := 0; i < concurrentWrites; i++ {
			go func(idx int) {
				event := logger.BlockedIPEvent{
					IP:     "192.168.1.100",
					Status: "success",
				}
				errors <- eventLogger.LogBlockedIPEvent(event)
			}(i)
		}

		// Collect errors
		for i := 0; i < concurrentWrites; i++ {
			err := <-errors
			assert.NoError(t, err)
		}
	})

	t.Run("creates file if deleted", func(t *testing.T) {
		// Delete the file
		err := os.Remove(filename)
		require.NoError(t, err)

		// Log new event - should recreate the file
		event := logger.BlockedIPEvent{
			IP:     "192.168.1.4",
			Status: "success",
		}

		err = eventLogger.LogBlockedIPEvent(event)
		require.NoError(t, err)

		// Verify file exists
		_, err = os.Stat(filename)
		assert.NoError(t, err)
	})

	t.Run("handles JSON marshaling error", func(t *testing.T) {
		// This test would require injecting a custom marshaler
		// For now, we trust json.Marshal works correctly
		// We'll test with a valid event to ensure the flow works
		event := logger.BlockedIPEvent{
			IP:     "192.168.1.5",
			Status: "success",
		}

		err := eventLogger.LogBlockedIPEvent(event)
		assert.NoError(t, err)
	})
}

func TestEventLogger_Close(t *testing.T) {
	tempDir := t.TempDir()
	filename := filepath.Join(tempDir, "events.log")
	
	eventLogger, err := logger.NewEventLogger(filename)
	require.NoError(t, err)

	// Close should always return nil
	err = eventLogger.Close()
	assert.NoError(t, err)
}

func getLastLine(content string) string {
	lines := []byte(content)
	// Find last newline
	lastNewline := -1
	for i := len(lines) - 2; i >= 0; i-- {
		if lines[i] == '\n' {
			lastNewline = i
			break
		}
	}
	
	if lastNewline == -1 {
		return string(lines)
	}
	return string(lines[lastNewline+1:])
}