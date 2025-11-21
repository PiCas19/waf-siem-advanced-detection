package logger

import (
	"encoding/json"
	"os"
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
	Duration     string    `json:"duration"` // "permanent", "temporary", "24 hours", etc
	Operator     string    `json:"operator"`   // Email dell'operatore che ha bloccato
	OperatorIP   string    `json:"operator_ip"` // IP da cui è stato fatto il blocco
	Status       string    `json:"status"`      // "success" o "failed"
}

// LogBlockedIPEvent scrive un evento di blocco manuale nel file di log
func (l *Logger) LogBlockedIPEvent(event BlockedIPEvent) error {
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
