package logger

import (
	"encoding/json"
	"log"
)

func (l *Logger) LogJSON(event map[string]interface{}) {
	data, _ := json.Marshal(event)
	log.Println(string(data))
}