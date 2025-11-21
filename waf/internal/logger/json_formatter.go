package logger

import (
	"encoding/json"
	"os"
	"path/filepath"
)

func (l *Logger) LogJSON(event map[string]interface{}) error {
	l.mutex.Lock()
	defer l.mutex.Unlock()

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