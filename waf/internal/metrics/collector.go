package metrics

import (
	"sync/atomic"
)

type MetricsCollector struct {
	totalRequests    uint64
	blockedRequests  uint64
	xssCount         uint64
	sqliCount        uint64
	lfiCount         uint64
	rfiCount         uint64
	cmdInjCount      uint64
}

func (m *MetricsCollector) IncTotal() {
	atomic.AddUint64(&m.totalRequests, 1)
}

func (m *MetricsCollector) IncBlocked() {
	atomic.AddUint64(&m.blockedRequests, 1)
}

func (m *MetricsCollector) IncXSS() {
	atomic.AddUint64(&m.xssCount, 1)
}

func (m *MetricsCollector) IncSQLi() {
	atomic.AddUint64(&m.sqliCount, 1)
}

func (m *MetricsCollector) IncLFI() {
	atomic.AddUint64(&m.lfiCount, 1)
}

func (m *MetricsCollector) IncRFI() {
	atomic.AddUint64(&m.rfiCount, 1)
}

func (m *MetricsCollector) IncCmdInj() {
	atomic.AddUint64(&m.cmdInjCount, 1)
}

func (m *MetricsCollector) GetStats() map[string]uint64 {
	return map[string]uint64{
		"total_requests":   atomic.LoadUint64(&m.totalRequests),
		"blocked_requests": atomic.LoadUint64(&m.blockedRequests),
		"xss_count":        atomic.LoadUint64(&m.xssCount),
		"sqli_count":       atomic.LoadUint64(&m.sqliCount),
		"lfi_count":        atomic.LoadUint64(&m.lfiCount),
		"rfi_count":        atomic.LoadUint64(&m.rfiCount),
		"cmd_inj_count":    atomic.LoadUint64(&m.cmdInjCount),
	}
}