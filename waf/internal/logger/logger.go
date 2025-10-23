package logger

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Logger handles structured logging for WAF events
type Logger struct {
	file  *os.File
	mutex sync.Mutex
}

// LogEntry represents a single WAF log entry
type LogEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	ThreatType  string    `json:"threat_type"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	ClientIP    string    `json:"client_ip"`
	Method      string    `json:"method"`
	URL         string    `json:"url"`
	UserAgent   string    `json:"user_agent"`
	Payload     string    `json:"payload"`
}

// NewLogger creates a new logger instance
func NewLogger(filename string) (*Logger, error) {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	
	return &Logger{file: f}, nil
}

// Log writes a log entry to the file
func (l *Logger) Log(entry LogEntry) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	
	// Add timestamp if not set
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}
	
	// Marshal to JSON
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	
	// Write to file
	_, err = l.file.Write(append(data, '\n'))
	return err
}

// Close closes the log file
func (l *Logger) Close() error {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	return l.file.Close()
}