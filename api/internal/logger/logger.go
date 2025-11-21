package logger

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Logger è l'istanza globale del logger
var Log *logrus.Logger

// InitLogger inizializza il logger con configurazione personalizzata
func InitLogger(logLevel string, outputPath string) error {
	Log = logrus.New()

	// Imposta il formato JSON per facile parsing
	Log.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: "2006-01-02T15:04:05Z07:00",
		PrettyPrint:     false,
	})

	// Imposta il livello di log
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		return err
	}
	Log.SetLevel(level)

	// Imposta l'output
	if outputPath == "stdout" || outputPath == "" {
		Log.SetOutput(os.Stdout)
	} else if outputPath == "stderr" {
		Log.SetOutput(os.Stderr)
	} else {
		// File output con append
		file, err := os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return err
		}
		Log.SetOutput(file)
	}

	return nil
}

// CloseLogger chiude i file descriptor se necessario
func CloseLogger() error {
	// Se l'output è un file, chiudilo
	if output := Log.Out; output != os.Stdout && output != os.Stderr {
		if closer, ok := output.(io.Closer); ok {
			return closer.Close()
		}
	}
	return nil
}

// WithRequestID crea un logger con request ID per tracciamento
func WithRequestID(requestID string) *logrus.Entry {
	return Log.WithField("request_id", requestID)
}

// WithUser crea un logger con informazioni utente
func WithUser(userID uint, email string) *logrus.Entry {
	return Log.WithFields(logrus.Fields{
		"user_id": userID,
		"email":   email,
	})
}

// WithError è un helper per loggare errori
func WithError(err error) *logrus.Entry {
	return Log.WithError(err)
}

// WithFields è un helper per aggiungere campi custom
func WithFields(fields logrus.Fields) *logrus.Entry {
	return Log.WithFields(fields)
}

// WAFLogger handles structured logging for WAF events
type WAFLogger struct {
	file  *os.File
	mutex sync.Mutex
}

// LogEntry represents a single WAF log entry with enhanced IP detection context
type LogEntry struct {
	Timestamp         time.Time `json:"timestamp"`
	ThreatType        string    `json:"threat_type"`
	Severity          string    `json:"severity"`
	Description       string    `json:"description"`
	ClientIP          string    `json:"client_ip"`
	ClientIPSource    string    `json:"client_ip_source"`    // How the IP was extracted: x-public-ip, x-forwarded-for, x-real-ip, remote-addr
	ClientIPTrusted   bool      `json:"client_ip_trusted"`   // Whether the IP source is from a trusted source
	ClientIPVPNReport bool      `json:"client_ip_vpn_report"` // Whether this is a self-reported IP from Tailscale/VPN client
	Method            string    `json:"method"`
	URL               string    `json:"url"`
	UserAgent         string    `json:"user_agent"`
	Payload           string    `json:"payload"`
	Blocked           bool      `json:"blocked"`             // Whether the request was blocked
	BlockedBy         string    `json:"blocked_by"`          // How it was blocked: "auto" (rule), "manual" (operator), or ""
}

// NewWAFLogger creates a new WAF logger instance
func NewWAFLogger(filename string) (*WAFLogger, error) {
	// Create directory if it doesn't exist
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	// Open/create the log file
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	return &WAFLogger{file: f}, nil
}

// Log writes a log entry to the file
func (l *WAFLogger) Log(entry LogEntry) error {
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
func (l *WAFLogger) Close() error {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	return l.file.Close()
}
