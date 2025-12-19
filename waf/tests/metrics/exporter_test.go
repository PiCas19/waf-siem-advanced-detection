package metrics

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/PiCas19/waf-siem-advanced-detection/waf/internal/metrics"
)

func TestMetricsCollector_ServeHTTP(t *testing.T) {
	collector := &metrics.MetricsCollector{}

	// Add some metrics
	collector.IncTotal()
	collector.IncTotal()
	collector.IncBlocked()
	collector.IncXSS()
	collector.IncSQLi()

	// Create test request
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	// Call ServeHTTP
	collector.ServeHTTP(w, req)

	// Check response code
	if w.Code != http.StatusOK {
		t.Errorf("Expected status code 200, got %d", w.Code)
	}

	// Check content type
	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", contentType)
	}

	// Parse JSON response
	var stats map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &stats)
	if err != nil {
		t.Fatalf("Failed to unmarshal JSON response: %v", err)
	}

	// Verify metrics values
	if stats["total_requests"].(float64) != 2 {
		t.Errorf("Expected total_requests to be 2, got %v", stats["total_requests"])
	}
	if stats["blocked_requests"].(float64) != 1 {
		t.Errorf("Expected blocked_requests to be 1, got %v", stats["blocked_requests"])
	}
	if stats["xss_count"].(float64) != 1 {
		t.Errorf("Expected xss_count to be 1, got %v", stats["xss_count"])
	}
	if stats["sqli_count"].(float64) != 1 {
		t.Errorf("Expected sqli_count to be 1, got %v", stats["sqli_count"])
	}
	if stats["lfi_count"].(float64) != 0 {
		t.Errorf("Expected lfi_count to be 0, got %v", stats["lfi_count"])
	}
	if stats["rfi_count"].(float64) != 0 {
		t.Errorf("Expected rfi_count to be 0, got %v", stats["rfi_count"])
	}
	if stats["cmd_inj_count"].(float64) != 0 {
		t.Errorf("Expected cmd_inj_count to be 0, got %v", stats["cmd_inj_count"])
	}
}

func TestMetricsCollector_ServeHTTP_EmptyMetrics(t *testing.T) {
	collector := &metrics.MetricsCollector{}

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	collector.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status code 200, got %d", w.Code)
	}

	var stats map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &stats)
	if err != nil {
		t.Fatalf("Failed to unmarshal JSON response: %v", err)
	}

	// All metrics should be 0
	for key, value := range stats {
		if value.(float64) != 0 {
			t.Errorf("Expected %s to be 0, got %v", key, value)
		}
	}
}

func TestMetricsCollector_ServeHTTP_MultipleRequests(t *testing.T) {
	collector := &metrics.MetricsCollector{}

	// Simulate multiple WAF requests
	for i := 0; i < 10; i++ {
		collector.IncTotal()
	}
	for i := 0; i < 5; i++ {
		collector.IncBlocked()
	}
	for i := 0; i < 3; i++ {
		collector.IncXSS()
	}

	// Make multiple HTTP requests to the metrics endpoint
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "/metrics", nil)
		w := httptest.NewRecorder()

		collector.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d: Expected status code 200, got %d", i, w.Code)
		}

		var stats map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &stats)
		if err != nil {
			t.Fatalf("Request %d: Failed to unmarshal JSON: %v", i, err)
		}

		// Metrics should be consistent across multiple requests
		if stats["total_requests"].(float64) != 10 {
			t.Errorf("Request %d: Expected total_requests to be 10, got %v", i, stats["total_requests"])
		}
		if stats["blocked_requests"].(float64) != 5 {
			t.Errorf("Request %d: Expected blocked_requests to be 5, got %v", i, stats["blocked_requests"])
		}
		if stats["xss_count"].(float64) != 3 {
			t.Errorf("Request %d: Expected xss_count to be 3, got %v", i, stats["xss_count"])
		}
	}
}

func TestMetricsCollector_ServeHTTP_POSTRequest(t *testing.T) {
	collector := &metrics.MetricsCollector{}
	collector.IncTotal()

	// Test with POST request (should still work)
	req := httptest.NewRequest("POST", "/metrics", nil)
	w := httptest.NewRecorder()

	collector.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status code 200, got %d", w.Code)
	}

	var stats map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &stats)
	if err != nil {
		t.Fatalf("Failed to unmarshal JSON response: %v", err)
	}

	if stats["total_requests"].(float64) != 1 {
		t.Errorf("Expected total_requests to be 1, got %v", stats["total_requests"])
	}
}

func TestMetricsCollector_ServeHTTP_AllMetricsTypes(t *testing.T) {
	collector := &metrics.MetricsCollector{}

	// Increment all metric types
	collector.IncTotal()
	collector.IncBlocked()
	collector.IncXSS()
	collector.IncSQLi()
	collector.IncLFI()
	collector.IncRFI()
	collector.IncCmdInj()

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	collector.ServeHTTP(w, req)

	var stats map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &stats)
	if err != nil {
		t.Fatalf("Failed to unmarshal JSON response: %v", err)
	}

	// Verify all metric types are present and equal to 1
	expectedKeys := []string{
		"total_requests", "blocked_requests", "xss_count",
		"sqli_count", "lfi_count", "rfi_count", "cmd_inj_count",
	}

	for _, key := range expectedKeys {
		if val, exists := stats[key]; !exists {
			t.Errorf("Expected key %s to exist in response", key)
		} else if val.(float64) != 1 {
			t.Errorf("Expected %s to be 1, got %v", key, val)
		}
	}
}

func TestMetricsCollector_ServeHTTP_LargeNumbers(t *testing.T) {
	collector := &metrics.MetricsCollector{}

	// Add large number of requests
	for i := 0; i < 1000000; i++ {
		collector.IncTotal()
		if i%2 == 0 {
			collector.IncBlocked()
		}
		if i%5 == 0 {
			collector.IncXSS()
		}
	}

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	collector.ServeHTTP(w, req)

	var stats map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &stats)
	if err != nil {
		t.Fatalf("Failed to unmarshal JSON response: %v", err)
	}

	if stats["total_requests"].(float64) != 1000000 {
		t.Errorf("Expected total_requests to be 1000000, got %v", stats["total_requests"])
	}
	if stats["blocked_requests"].(float64) != 500000 {
		t.Errorf("Expected blocked_requests to be 500000, got %v", stats["blocked_requests"])
	}
	if stats["xss_count"].(float64) != 200000 {
		t.Errorf("Expected xss_count to be 200000, got %v", stats["xss_count"])
	}
}

func BenchmarkMetricsCollector_ServeHTTP(b *testing.B) {
	collector := &metrics.MetricsCollector{}
	collector.IncTotal()
	collector.IncBlocked()
	collector.IncXSS()

	req := httptest.NewRequest("GET", "/metrics", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		collector.ServeHTTP(w, req)
	}
}
