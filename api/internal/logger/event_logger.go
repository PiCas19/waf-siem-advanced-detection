package logger

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// BlockedIPEvent rappresenta un evento di blocco manuale di un IP
type BlockedIPEvent struct {
	Timestamp    time.Time `json:"timestamp"`
	EventType    string    `json:"event_type"` // "ip_blocked_manual"
	IP           string    `json:"ip"`
	ThreatType   string    `json:"threat_type"`
	Severity     string    `json:"severity"`
	Description  string    `json:"description"`
	Reason       string    `json:"reason"`
	Duration     string    `json:"duration"` // "permanent", "temporary", "X hours", etc
	Operator     string    `json:"operator"`   // Email dell'operatore che ha bloccato
	OperatorIP   string    `json:"operator_ip"` // IP da cui è stato fatto il blocco
	Status       string    `json:"status"`      // "success" o "failed"
}

// EventLogger handles logging of security events
type EventLogger struct {
	filename string
	mutex    sync.Mutex
}

// NewEventLogger creates a new event logger instance
func NewEventLogger(filename string) (*EventLogger, error) {
	// Create directory if it doesn't exist
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	// Verify we can write to the file (open and close immediately)
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	f.Close() // Close immediately - we'll open on each write

	return &EventLogger{filename: filename}, nil
}

// LogBlockedIPEvent scrive un evento di blocco manuale nel file di log
func (l *EventLogger) LogBlockedIPEvent(event BlockedIPEvent) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	// Add timestamp if not set
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Ensure event_type is set
	if event.EventType == "" {
		event.EventType = "ip_blocked_manual"
	}

	// Marshal to JSON
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	// Create directory if it doesn't exist (in case it was deleted)
	dir := filepath.Dir(l.filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Open file, write, and close (handles file recreation if deleted)
	f, err := os.OpenFile(l.filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	// Write to file
	_, err = f.Write(append(data, '\n'))
	return err
}

// Close is a no-op for this implementation (file is closed after each write)
func (l *EventLogger) Close() error {
	return nil
}
