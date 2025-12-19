package metrics

import (
	"sync"
	"testing"

	"github.com/PiCas19/waf-siem-advanced-detection/waf/internal/metrics"
)

func TestMetricsCollector_IncTotal(t *testing.T) {
	collector := &metrics.MetricsCollector{}

	// Test initial state
	stats := collector.GetStats()
	if stats["total_requests"] != 0 {
		t.Errorf("Expected initial total_requests to be 0, got %d", stats["total_requests"])
	}

	// Test increment
	collector.IncTotal()
	stats = collector.GetStats()
	if stats["total_requests"] != 1 {
		t.Errorf("Expected total_requests to be 1, got %d", stats["total_requests"])
	}

	// Test multiple increments
	for i := 0; i < 10; i++ {
		collector.IncTotal()
	}
	stats = collector.GetStats()
	if stats["total_requests"] != 11 {
		t.Errorf("Expected total_requests to be 11, got %d", stats["total_requests"])
	}
}

func TestMetricsCollector_IncBlocked(t *testing.T) {
	collector := &metrics.MetricsCollector{}

	collector.IncBlocked()
	stats := collector.GetStats()
	if stats["blocked_requests"] != 1 {
		t.Errorf("Expected blocked_requests to be 1, got %d", stats["blocked_requests"])
	}

	for i := 0; i < 5; i++ {
		collector.IncBlocked()
	}
	stats = collector.GetStats()
	if stats["blocked_requests"] != 6 {
		t.Errorf("Expected blocked_requests to be 6, got %d", stats["blocked_requests"])
	}
}

func TestMetricsCollector_IncXSS(t *testing.T) {
	collector := &metrics.MetricsCollector{}

	collector.IncXSS()
	stats := collector.GetStats()
	if stats["xss_count"] != 1 {
		t.Errorf("Expected xss_count to be 1, got %d", stats["xss_count"])
	}

	for i := 0; i < 3; i++ {
		collector.IncXSS()
	}
	stats = collector.GetStats()
	if stats["xss_count"] != 4 {
		t.Errorf("Expected xss_count to be 4, got %d", stats["xss_count"])
	}
}

func TestMetricsCollector_IncSQLi(t *testing.T) {
	collector := &metrics.MetricsCollector{}

	collector.IncSQLi()
	stats := collector.GetStats()
	if stats["sqli_count"] != 1 {
		t.Errorf("Expected sqli_count to be 1, got %d", stats["sqli_count"])
	}

	for i := 0; i < 7; i++ {
		collector.IncSQLi()
	}
	stats = collector.GetStats()
	if stats["sqli_count"] != 8 {
		t.Errorf("Expected sqli_count to be 8, got %d", stats["sqli_count"])
	}
}

func TestMetricsCollector_IncLFI(t *testing.T) {
	collector := &metrics.MetricsCollector{}

	collector.IncLFI()
	stats := collector.GetStats()
	if stats["lfi_count"] != 1 {
		t.Errorf("Expected lfi_count to be 1, got %d", stats["lfi_count"])
	}

	for i := 0; i < 2; i++ {
		collector.IncLFI()
	}
	stats = collector.GetStats()
	if stats["lfi_count"] != 3 {
		t.Errorf("Expected lfi_count to be 3, got %d", stats["lfi_count"])
	}
}

func TestMetricsCollector_IncRFI(t *testing.T) {
	collector := &metrics.MetricsCollector{}

	collector.IncRFI()
	stats := collector.GetStats()
	if stats["rfi_count"] != 1 {
		t.Errorf("Expected rfi_count to be 1, got %d", stats["rfi_count"])
	}

	for i := 0; i < 4; i++ {
		collector.IncRFI()
	}
	stats = collector.GetStats()
	if stats["rfi_count"] != 5 {
		t.Errorf("Expected rfi_count to be 5, got %d", stats["rfi_count"])
	}
}

func TestMetricsCollector_IncCmdInj(t *testing.T) {
	collector := &metrics.MetricsCollector{}

	collector.IncCmdInj()
	stats := collector.GetStats()
	if stats["cmd_inj_count"] != 1 {
		t.Errorf("Expected cmd_inj_count to be 1, got %d", stats["cmd_inj_count"])
	}

	for i := 0; i < 6; i++ {
		collector.IncCmdInj()
	}
	stats = collector.GetStats()
	if stats["cmd_inj_count"] != 7 {
		t.Errorf("Expected cmd_inj_count to be 7, got %d", stats["cmd_inj_count"])
	}
}

func TestMetricsCollector_GetStats(t *testing.T) {
	collector := &metrics.MetricsCollector{}

	// Test empty stats
	stats := collector.GetStats()
	if len(stats) != 7 {
		t.Errorf("Expected 7 stat keys, got %d", len(stats))
	}

	// Verify all keys exist
	expectedKeys := []string{
		"total_requests", "blocked_requests", "xss_count",
		"sqli_count", "lfi_count", "rfi_count", "cmd_inj_count",
	}
	for _, key := range expectedKeys {
		if _, exists := stats[key]; !exists {
			t.Errorf("Expected key %s to exist in stats", key)
		}
	}

	// Test with some data
	collector.IncTotal()
	collector.IncBlocked()
	collector.IncXSS()
	collector.IncSQLi()
	collector.IncLFI()
	collector.IncRFI()
	collector.IncCmdInj()

	stats = collector.GetStats()
	for _, key := range expectedKeys {
		if stats[key] != 1 {
			t.Errorf("Expected %s to be 1, got %d", key, stats[key])
		}
	}
}

func TestMetricsCollector_ConcurrentIncrements(t *testing.T) {
	collector := &metrics.MetricsCollector{}
	concurrency := 100
	incrementsPerGoroutine := 100

	var wg sync.WaitGroup
	wg.Add(concurrency * 7) // 7 different increment functions

	// Test concurrent IncTotal
	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < incrementsPerGoroutine; j++ {
				collector.IncTotal()
			}
		}()
	}

	// Test concurrent IncBlocked
	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < incrementsPerGoroutine; j++ {
				collector.IncBlocked()
			}
		}()
	}

	// Test concurrent IncXSS
	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < incrementsPerGoroutine; j++ {
				collector.IncXSS()
			}
		}()
	}

	// Test concurrent IncSQLi
	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < incrementsPerGoroutine; j++ {
				collector.IncSQLi()
			}
		}()
	}

	// Test concurrent IncLFI
	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < incrementsPerGoroutine; j++ {
				collector.IncLFI()
			}
		}()
	}

	// Test concurrent IncRFI
	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < incrementsPerGoroutine; j++ {
				collector.IncRFI()
			}
		}()
	}

	// Test concurrent IncCmdInj
	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < incrementsPerGoroutine; j++ {
				collector.IncCmdInj()
			}
		}()
	}

	wg.Wait()

	expected := uint64(concurrency * incrementsPerGoroutine)
	stats := collector.GetStats()

	if stats["total_requests"] != expected {
		t.Errorf("Expected total_requests to be %d, got %d", expected, stats["total_requests"])
	}
	if stats["blocked_requests"] != expected {
		t.Errorf("Expected blocked_requests to be %d, got %d", expected, stats["blocked_requests"])
	}
	if stats["xss_count"] != expected {
		t.Errorf("Expected xss_count to be %d, got %d", expected, stats["xss_count"])
	}
	if stats["sqli_count"] != expected {
		t.Errorf("Expected sqli_count to be %d, got %d", expected, stats["sqli_count"])
	}
	if stats["lfi_count"] != expected {
		t.Errorf("Expected lfi_count to be %d, got %d", expected, stats["lfi_count"])
	}
	if stats["rfi_count"] != expected {
		t.Errorf("Expected rfi_count to be %d, got %d", expected, stats["rfi_count"])
	}
	if stats["cmd_inj_count"] != expected {
		t.Errorf("Expected cmd_inj_count to be %d, got %d", expected, stats["cmd_inj_count"])
	}
}

func TestMetricsCollector_MixedOperations(t *testing.T) {
	collector := &metrics.MetricsCollector{}

	// Simulate realistic WAF behavior
	collector.IncTotal() // Request 1
	collector.IncTotal() // Request 2 - XSS detected
	collector.IncXSS()
	collector.IncBlocked()

	collector.IncTotal() // Request 3 - SQLi detected
	collector.IncSQLi()
	collector.IncBlocked()

	collector.IncTotal() // Request 4 - Clean

	collector.IncTotal() // Request 5 - LFI detected
	collector.IncLFI()
	collector.IncBlocked()

	stats := collector.GetStats()

	if stats["total_requests"] != 5 {
		t.Errorf("Expected total_requests to be 5, got %d", stats["total_requests"])
	}
	if stats["blocked_requests"] != 3 {
		t.Errorf("Expected blocked_requests to be 3, got %d", stats["blocked_requests"])
	}
	if stats["xss_count"] != 1 {
		t.Errorf("Expected xss_count to be 1, got %d", stats["xss_count"])
	}
	if stats["sqli_count"] != 1 {
		t.Errorf("Expected sqli_count to be 1, got %d", stats["sqli_count"])
	}
	if stats["lfi_count"] != 1 {
		t.Errorf("Expected lfi_count to be 1, got %d", stats["lfi_count"])
	}
	if stats["rfi_count"] != 0 {
		t.Errorf("Expected rfi_count to be 0, got %d", stats["rfi_count"])
	}
	if stats["cmd_inj_count"] != 0 {
		t.Errorf("Expected cmd_inj_count to be 0, got %d", stats["cmd_inj_count"])
	}
}

func BenchmarkMetricsCollector_IncTotal(b *testing.B) {
	collector := &metrics.MetricsCollector{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		collector.IncTotal()
	}
}

func BenchmarkMetricsCollector_GetStats(b *testing.B) {
	collector := &metrics.MetricsCollector{}
	collector.IncTotal()
	collector.IncBlocked()
	collector.IncXSS()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = collector.GetStats()
	}
}

func BenchmarkMetricsCollector_ConcurrentIncrements(b *testing.B) {
	collector := &metrics.MetricsCollector{}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			collector.IncTotal()
		}
	})
}
