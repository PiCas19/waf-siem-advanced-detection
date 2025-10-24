package metrics

import (
	"encoding/json"
	"net/http"
)

func (m *MetricsCollector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	stats := m.GetStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}