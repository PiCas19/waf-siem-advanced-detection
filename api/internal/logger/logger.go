package logger

import (
	"io"
	"os"

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
