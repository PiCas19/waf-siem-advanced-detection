package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/api"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/service"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/websocket"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// TestInitTIService_WithBothAPIKeys tests initialization with both API keys set
func TestInitTIService_WithBothAPIKeys(t *testing.T) {
	// Set environment variables
	os.Setenv("VIRUSTOTAL_API_KEY", "test_virustotal_key")
	os.Setenv("ABUSEIPDB_API_KEY", "test_abuseipdb_key")
	defer func() {
		os.Unsetenv("VIRUSTOTAL_API_KEY")
		os.Unsetenv("ABUSEIPDB_API_KEY")
	}()

	// Create in-memory database
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Should not panic
	assert.NotPanics(t, func() {
		api.InitTIService(db)
	})
}

// TestInitTIService_WithVirusTotalOnly tests initialization with only VirusTotal key
func TestInitTIService_WithVirusTotalOnly(t *testing.T) {
	// Set only VirusTotal key
	os.Setenv("VIRUSTOTAL_API_KEY", "test_virustotal_key")
	os.Unsetenv("ABUSEIPDB_API_KEY")
	defer os.Unsetenv("VIRUSTOTAL_API_KEY")

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	assert.NotPanics(t, func() {
		api.InitTIService(db)
	})
}

// TestInitTIService_WithAbuseIPDBOnly tests initialization with only AbuseIPDB key
func TestInitTIService_WithAbuseIPDBOnly(t *testing.T) {
	// Set only AbuseIPDB key
	os.Unsetenv("VIRUSTOTAL_API_KEY")
	os.Setenv("ABUSEIPDB_API_KEY", "test_abuseipdb_key")
	defer os.Unsetenv("ABUSEIPDB_API_KEY")

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	assert.NotPanics(t, func() {
		api.InitTIService(db)
	})
}

// TestInitTIService_WithNoAPIKeys tests initialization without any API keys
func TestInitTIService_WithNoAPIKeys(t *testing.T) {
	// Ensure no keys are set
	os.Unsetenv("VIRUSTOTAL_API_KEY")
	os.Unsetenv("ABUSEIPDB_API_KEY")

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	assert.NotPanics(t, func() {
		api.InitTIService(db)
	})
}

// TestGetSeverityFromThreatType_CriticalThreats tests critical severity threats
func TestGetSeverityFromThreatType_CriticalThreats(t *testing.T) {
	criticalThreats := []string{
		"SQL_INJECTION",
		"COMMAND_INJECTION",
		"XXE",
		"LDAP_INJECTION",
		"RFI",
		"SSTI",
	}

	for _, threat := range criticalThreats {
		severity := api.GetSeverityFromThreatType(threat)
		assert.Equal(t, "Critical", severity, "Threat %s should be Critical", threat)
	}
}

// TestGetSeverityFromThreatType_HighThreats tests high severity threats
func TestGetSeverityFromThreatType_HighThreats(t *testing.T) {
	highThreats := []string{
		"XSS",
		"LFI",
		"PATH_TRAVERSAL",
		"SSRF",
		"NOSQL_INJECTION",
		"HTTP_RESPONSE_SPLITTING",
	}

	for _, threat := range highThreats {
		severity := api.GetSeverityFromThreatType(threat)
		assert.Equal(t, "High", severity, "Threat %s should be High", threat)
	}
}

// TestGetSeverityFromThreatType_MediumThreats tests medium severity threats
func TestGetSeverityFromThreatType_MediumThreats(t *testing.T) {
	severity := api.GetSeverityFromThreatType("PROTOTYPE_POLLUTION")
	assert.Equal(t, "Medium", severity)
}

// TestGetSeverityFromThreatType_UnknownThreat tests default severity for unknown threats
func TestGetSeverityFromThreatType_UnknownThreat(t *testing.T) {
	severity := api.GetSeverityFromThreatType("UNKNOWN_THREAT")
	assert.Equal(t, "Medium", severity, "Unknown threats should default to Medium")
}

// TestNewWAFEventHandler_Success tests successful WAF event handling
func TestNewWAFEventHandler_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create in-memory database and initialize TI service
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	api.InitTIService(db)

	mockLogRepo := new(MockLogRepository)
	mockAuditLogRepo := new(MockAuditLogRepository)
	mockRuleRepo := new(MockRuleRepository)
	mockBlocklistRepo := new(MockBlocklistRepository)

	logService := service.NewLogService(mockLogRepo)
	auditLogService := service.NewAuditLogService(mockAuditLogRepo)
	ruleService := service.NewRuleService(mockRuleRepo)
	blocklistService := service.NewBlocklistService(mockBlocklistRepo, mockLogRepo)

	// Mock rule lookup
	mockRuleRepo.On("FindAll", mock.Anything).Return([]models.Rule{
		{
			ID:       1,
			Name:     "XSS Rule",
			Type:     "XSS",
			Pattern:  "<script>",
			Severity: "High",
			Enabled:  true,
		},
	}, nil).Once()

	// Mock log creation
	mockLogRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.Log")).
		Run(func(args mock.Arguments) {
			log := args.Get(1).(*models.Log)
			assert.Equal(t, "192.168.1.100", log.ClientIP)
			assert.Equal(t, "XSS", log.ThreatType)
			assert.Equal(t, "High", log.Severity)
			assert.Equal(t, false, log.Blocked)
		}).Return(nil).Once()

	handler := api.NewWAFEventHandler(logService, auditLogService, ruleService, blocklistService)

	// Create test request
	event := websocket.WAFEvent{
		IP:      "192.168.1.100",
		Threat:  "XSS",
		Method:  "GET",
		Path:    "/test",
		Blocked: false,
	}
	jsonData, _ := json.Marshal(event)

	req, _ := http.NewRequest("POST", "/api/waf/event", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert response
	assert.Equal(t, 200, w.Code)

	// Verify mock expectations
	mockRuleRepo.AssertExpectations(t)
	mockLogRepo.AssertExpectations(t)
}

// TestNewWAFEventHandler_WithXPublicIP tests IP extraction with X-Public-IP header
func TestNewWAFEventHandler_WithXPublicIP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create in-memory database and initialize TI service
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	api.InitTIService(db)

	mockLogRepo := new(MockLogRepository)
	mockAuditLogRepo := new(MockAuditLogRepository)
	mockRuleRepo := new(MockRuleRepository)
	mockBlocklistRepo := new(MockBlocklistRepository)

	logService := service.NewLogService(mockLogRepo)
	auditLogService := service.NewAuditLogService(mockAuditLogRepo)
	ruleService := service.NewRuleService(mockRuleRepo)
	blocklistService := service.NewBlocklistService(mockBlocklistRepo, mockLogRepo)

	// Mock rule lookup
	mockRuleRepo.On("FindAll", mock.Anything).Return([]models.Rule{}, nil).Once()

	// Mock log creation - should use X-Public-IP value
	mockLogRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.Log")).
		Run(func(args mock.Arguments) {
			log := args.Get(1).(*models.Log)
			assert.Equal(t, "203.0.113.45", log.ClientIP, "Should use X-Public-IP header value")
		}).Return(nil).Once()

	handler := api.NewWAFEventHandler(logService, auditLogService, ruleService, blocklistService)

	// Create test request with X-Public-IP header
	event := websocket.WAFEvent{
		IP:      "10.0.0.1", // Internal IP
		Threat:  "SQL_INJECTION",
		Method:  "POST",
		Path:    "/api/data",
		Blocked: false,
	}
	jsonData, _ := json.Marshal(event)

	req, _ := http.NewRequest("POST", "/api/waf/event", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Public-IP", "203.0.113.45") // Public IP from Tailscale/VPN

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert response
	assert.Equal(t, 200, w.Code)

	// Verify mock expectations
	mockRuleRepo.AssertExpectations(t)
	mockLogRepo.AssertExpectations(t)
}

// TestNewWAFEventHandler_WithXForwardedFor tests IP extraction with X-Forwarded-For header
func TestNewWAFEventHandler_WithXForwardedFor(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create in-memory database and initialize TI service
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	api.InitTIService(db)

	mockLogRepo := new(MockLogRepository)
	mockAuditLogRepo := new(MockAuditLogRepository)
	mockRuleRepo := new(MockRuleRepository)
	mockBlocklistRepo := new(MockBlocklistRepository)

	logService := service.NewLogService(mockLogRepo)
	auditLogService := service.NewAuditLogService(mockAuditLogRepo)
	ruleService := service.NewRuleService(mockRuleRepo)
	blocklistService := service.NewBlocklistService(mockBlocklistRepo, mockLogRepo)

	// Mock rule lookup
	mockRuleRepo.On("FindAll", mock.Anything).Return([]models.Rule{}, nil).Once()

	// Mock log creation
	mockLogRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.Log")).
		Run(func(args mock.Arguments) {
			log := args.Get(1).(*models.Log)
			assert.Equal(t, "198.51.100.10", log.ClientIP, "Should use first IP from X-Forwarded-For")
		}).Return(nil).Once()

	handler := api.NewWAFEventHandler(logService, auditLogService, ruleService, blocklistService)

	// Create test request with X-Forwarded-For header
	event := websocket.WAFEvent{
		IP:      "10.0.0.1",
		Threat:  "XSS",
		Method:  "GET",
		Path:    "/test",
		Blocked: false,
	}
	jsonData, _ := json.Marshal(event)

	req, _ := http.NewRequest("POST", "/api/waf/event", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "198.51.100.10, 192.0.2.1") // Multiple IPs, takes first

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert response
	assert.Equal(t, 200, w.Code)

	// Verify mock expectations
	mockRuleRepo.AssertExpectations(t)
	mockLogRepo.AssertExpectations(t)
}

// TestNewWAFEventHandler_BlockedEvent tests handling of blocked events
func TestNewWAFEventHandler_BlockedEvent(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create in-memory database and initialize TI service
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	api.InitTIService(db)

	mockLogRepo := new(MockLogRepository)
	mockAuditLogRepo := new(MockAuditLogRepository)
	mockRuleRepo := new(MockRuleRepository)
	mockBlocklistRepo := new(MockBlocklistRepository)

	logService := service.NewLogService(mockLogRepo)
	auditLogService := service.NewAuditLogService(mockAuditLogRepo)
	ruleService := service.NewRuleService(mockRuleRepo)
	blocklistService := service.NewBlocklistService(mockBlocklistRepo, mockLogRepo)

	// Mock rule lookup
	mockRuleRepo.On("FindAll", mock.Anything).Return([]models.Rule{}, nil).Once()

	// Mock log creation
	mockLogRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.Log")).
		Run(func(args mock.Arguments) {
			log := args.Get(1).(*models.Log)
			assert.Equal(t, true, log.Blocked, "Event should be blocked")
			assert.Equal(t, "coraza", log.BlockedBy, "Should be blocked by coraza")
		}).Return(nil).Once()

	handler := api.NewWAFEventHandler(logService, auditLogService, ruleService, blocklistService)

	// Create test request with blocked event
	event := websocket.WAFEvent{
		IP:        "192.168.1.100",
		Threat:    "SQL_INJECTION",
		Method:    "POST",
		Path:      "/api/data",
		Blocked:   true,
		BlockedBy: "coraza",
	}
	jsonData, _ := json.Marshal(event)

	req, _ := http.NewRequest("POST", "/api/waf/event", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert response
	assert.Equal(t, 200, w.Code)

	// Verify mock expectations
	mockRuleRepo.AssertExpectations(t)
	mockLogRepo.AssertExpectations(t)
}

// TestNewWAFEventHandler_InvalidJSON tests handling of invalid JSON
func TestNewWAFEventHandler_InvalidJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockLogRepo := new(MockLogRepository)
	mockAuditLogRepo := new(MockAuditLogRepository)
	mockRuleRepo := new(MockRuleRepository)
	mockBlocklistRepo := new(MockBlocklistRepository)

	logService := service.NewLogService(mockLogRepo)
	auditLogService := service.NewAuditLogService(mockAuditLogRepo)
	ruleService := service.NewRuleService(mockRuleRepo)
	blocklistService := service.NewBlocklistService(mockBlocklistRepo, mockLogRepo)

	handler := api.NewWAFEventHandler(logService, auditLogService, ruleService, blocklistService)

	// Create test request with invalid JSON
	req, _ := http.NewRequest("POST", "/api/waf/event", bytes.NewBufferString("{invalid json"))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert error response
	assert.Equal(t, 400, w.Code)

	// Verify no service calls were made
	mockRuleRepo.AssertNotCalled(t, "FindAll")
	mockLogRepo.AssertNotCalled(t, "Create")
}

// TestNewWAFEventHandler_RuleServiceError tests handling of rule service errors
func TestNewWAFEventHandler_RuleServiceError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create in-memory database and initialize TI service
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	api.InitTIService(db)

	mockLogRepo := new(MockLogRepository)
	mockAuditLogRepo := new(MockAuditLogRepository)
	mockRuleRepo := new(MockRuleRepository)
	mockBlocklistRepo := new(MockBlocklistRepository)

	logService := service.NewLogService(mockLogRepo)
	auditLogService := service.NewAuditLogService(mockAuditLogRepo)
	ruleService := service.NewRuleService(mockRuleRepo)
	blocklistService := service.NewBlocklistService(mockBlocklistRepo, mockLogRepo)

	// Mock rule lookup to return error
	mockRuleRepo.On("FindAll", mock.Anything).Return([]models.Rule{}, errors.New("database error")).Once()

	// Mock log creation (should still work with default severity)
	mockLogRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.Log")).
		Run(func(args mock.Arguments) {
			log := args.Get(1).(*models.Log)
			assert.Equal(t, "Medium", log.Severity, "Should use default severity on rule fetch error")
		}).Return(nil).Once()

	handler := api.NewWAFEventHandler(logService, auditLogService, ruleService, blocklistService)

	// Create test request
	event := websocket.WAFEvent{
		IP:      "192.168.1.100",
		Threat:  "XSS",
		Method:  "GET",
		Path:    "/test",
		Blocked: false,
	}
	jsonData, _ := json.Marshal(event)

	req, _ := http.NewRequest("POST", "/api/waf/event", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert response (should still succeed)
	assert.Equal(t, 200, w.Code)

	// Verify mock expectations
	mockRuleRepo.AssertExpectations(t)
	mockLogRepo.AssertExpectations(t)
}

// TestWAFStatsHandler_Success tests successful stats retrieval
func TestWAFStatsHandler_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create in-memory database
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Auto-migrate models
	err = db.AutoMigrate(&models.Log{})
	require.NoError(t, err)

	// Set the stats DB
	api.SetStatsDB(db)

	// Insert test logs
	testLogs := []models.Log{
		{
			ClientIP:   "192.168.1.100",
			ThreatType: "XSS",
			Method:     "GET",
			URL:        "/test1",
			Blocked:    true,
			Severity:   "High",
			CreatedAt:  time.Now(),
		},
		{
			ClientIP:   "192.168.1.101",
			ThreatType: "SQL_INJECTION",
			Method:     "POST",
			URL:        "/test2",
			Blocked:    false,
			Severity:   "Critical",
			CreatedAt:  time.Now(),
		},
		{
			ClientIP:   "192.168.1.102",
			ThreatType: "XSS",
			Method:     "GET",
			URL:        "/test3",
			Blocked:    true,
			Severity:   "High",
			CreatedAt:  time.Now(),
		},
	}

	for _, log := range testLogs {
		db.Create(&log)
	}

	// Create test request
	req, _ := http.NewRequest("GET", "/api/stats", nil)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	api.WAFStatsHandler(c)

	// Assert response
	assert.Equal(t, 200, w.Code)

	var stats map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &stats)
	require.NoError(t, err)

	// Verify stats
	assert.Equal(t, float64(2), stats["requests_blocked"], "Should have 2 blocked requests")
	assert.Equal(t, float64(1), stats["threats_detected"], "Should have 1 detected threat")
	assert.Equal(t, float64(3), stats["total_requests"], "Should have 3 total events")
	assert.NotEmpty(t, stats["recent"], "Should have recent events")
}

// TestWAFStatsHandler_EmptyDatabase tests stats with no logs
func TestWAFStatsHandler_EmptyDatabase(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create in-memory database
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Auto-migrate models
	err = db.AutoMigrate(&models.Log{})
	require.NoError(t, err)

	// Set the stats DB
	api.SetStatsDB(db)

	// Create test request
	req, _ := http.NewRequest("GET", "/api/stats", nil)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	api.WAFStatsHandler(c)

	// Assert response
	assert.Equal(t, 200, w.Code)

	var stats map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &stats)
	require.NoError(t, err)

	// Verify zero stats
	assert.Equal(t, float64(0), stats["requests_blocked"])
	assert.Equal(t, float64(0), stats["threats_detected"])
	assert.Equal(t, float64(0), stats["total_requests"])
}

// TestWAFStatsHandler_WithDetectedLogs tests stats with detected but not blocked logs
func TestWAFStatsHandler_WithDetectedLogs(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create in-memory database
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Auto-migrate models
	err = db.AutoMigrate(&models.Log{})
	require.NoError(t, err)

	// Set the stats DB
	api.SetStatsDB(db)

	// Create detected logs (blocked = false)
	detectedLogs := []models.Log{
		{ClientIP: "192.168.1.1", ThreatType: "XSS", Blocked: false, Payload: "test1"},
		{ClientIP: "192.168.1.2", ThreatType: "SQLi", Blocked: false, Payload: "test2"},
		{ClientIP: "192.168.1.3", ThreatType: "RCE", Blocked: false, Payload: "test3"},
	}
	for _, log := range detectedLogs {
		err := db.Create(&log).Error
		require.NoError(t, err)
	}

	// Create test request
	req, _ := http.NewRequest("GET", "/api/stats", nil)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	api.WAFStatsHandler(c)

	// Assert response
	assert.Equal(t, 200, w.Code)

	var stats map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &stats)
	require.NoError(t, err)

	// Verify stats: 3 detected, 0 blocked
	assert.Equal(t, float64(0), stats["requests_blocked"])
	assert.Equal(t, float64(3), stats["threats_detected"])
	assert.Equal(t, float64(3), stats["total_requests"])
}

// TestWAFStatsHandler_WithBlockedLogs tests stats with blocked logs
func TestWAFStatsHandler_WithBlockedLogs(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create in-memory database
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Auto-migrate models
	err = db.AutoMigrate(&models.Log{})
	require.NoError(t, err)

	// Set the stats DB
	api.SetStatsDB(db)

	// Create blocked logs (blocked = true)
	blockedLogs := []models.Log{
		{ClientIP: "10.0.0.1", ThreatType: "XSS", Blocked: true, BlockedBy: "rule-1", Payload: "test1"},
		{ClientIP: "10.0.0.2", ThreatType: "SQLi", Blocked: true, BlockedBy: "rule-2", Payload: "test2"},
	}
	for _, log := range blockedLogs {
		err := db.Create(&log).Error
		require.NoError(t, err)
	}

	// Create test request
	req, _ := http.NewRequest("GET", "/api/stats", nil)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	api.WAFStatsHandler(c)

	// Assert response
	assert.Equal(t, 200, w.Code)

	var stats map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &stats)
	require.NoError(t, err)

	// Verify stats: 0 detected, 2 blocked
	assert.Equal(t, float64(2), stats["requests_blocked"])
	assert.Equal(t, float64(0), stats["threats_detected"])
	assert.Equal(t, float64(2), stats["total_requests"])
}

// TestWAFStatsHandler_WithMixedLogs tests stats with mixed detected and blocked logs
func TestWAFStatsHandler_WithMixedLogs(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create in-memory database
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Auto-migrate models
	err = db.AutoMigrate(&models.Log{})
	require.NoError(t, err)

	// Set the stats DB
	api.SetStatsDB(db)

	// Create mixed logs
	logs := []models.Log{
		{ClientIP: "192.168.1.1", ThreatType: "XSS", Blocked: false, Payload: "test1"},
		{ClientIP: "192.168.1.2", ThreatType: "SQLi", Blocked: true, BlockedBy: "rule-1", Payload: "test2"},
		{ClientIP: "192.168.1.3", ThreatType: "RCE", Blocked: false, Payload: "test3"},
		{ClientIP: "192.168.1.4", ThreatType: "LFI", Blocked: true, BlockedBy: "rule-2", Payload: "test4"},
		{ClientIP: "192.168.1.5", ThreatType: "XSS", Blocked: true, BlockedBy: "rule-3", Payload: "test5"},
	}
	for _, log := range logs {
		err := db.Create(&log).Error
		require.NoError(t, err)
	}

	// Create test request
	req, _ := http.NewRequest("GET", "/api/stats", nil)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	api.WAFStatsHandler(c)

	// Assert response
	assert.Equal(t, 200, w.Code)

	var stats map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &stats)
	require.NoError(t, err)

	// Verify stats: 2 detected, 3 blocked, 5 total
	assert.Equal(t, float64(3), stats["requests_blocked"])
	assert.Equal(t, float64(2), stats["threats_detected"])
	assert.Equal(t, float64(5), stats["total_requests"])

	// Verify recent events are returned
	recent, ok := stats["recent"].([]interface{})
	assert.True(t, ok, "Recent should be an array")
	assert.LessOrEqual(t, len(recent), 5, "Should return at most 5 recent events")
}

// TestWAFStatsHandler_MemoryFallback tests fallback when statsDB is nil
func TestWAFStatsHandler_MemoryFallback(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Set statsDB to nil to trigger memory fallback
	api.SetStatsDB(nil)

	// Create test request
	req, _ := http.NewRequest("GET", "/api/stats", nil)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	api.WAFStatsHandler(c)

	// Assert response
	assert.Equal(t, 200, w.Code)

	var stats map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &stats)
	require.NoError(t, err)

	// Should return some stats structure (memory-based)
	assert.Contains(t, stats, "requests_blocked")
	assert.Contains(t, stats, "threats_detected")
	assert.Contains(t, stats, "total_requests")
}

// TestGetGeolocationHandler_Success tests successful geolocation data retrieval
func TestGetGeolocationHandler_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create in-memory database
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Auto-migrate models
	err = db.AutoMigrate(&models.Log{})
	require.NoError(t, err)

	// Insert test logs with geolocation data
	testLogs := []models.Log{
		{
			ClientIP:   "192.168.1.100",
			ThreatType: "XSS",
			Country:    "United States",
			CreatedAt:  time.Now(),
		},
		{
			ClientIP:   "192.168.1.101",
			ThreatType: "SQL_INJECTION",
			Country:    "United Kingdom",
			CreatedAt:  time.Now(),
		},
		{
			ClientIP:   "192.168.1.102",
			ThreatType: "XSS",
			Country:    "United States",
			CreatedAt:  time.Now(),
		},
	}

	for _, log := range testLogs {
		db.Create(&log)
	}

	// Create test request
	req, _ := http.NewRequest("GET", "/api/geolocation", nil)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler := api.GetGeolocationHandler(db)
	handler(c)

	// Assert response
	assert.Equal(t, 200, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	// Verify geolocation data
	data, ok := response["data"]
	assert.True(t, ok, "Response should have 'data' field")
	dataArray, ok := data.([]interface{})
	assert.True(t, ok, "Data should be an array")
	assert.GreaterOrEqual(t, len(dataArray), 1, "Should have geolocation data")
}

// TestGetGeolocationHandler_EmptyDatabase tests geolocation with no logs
func TestGetGeolocationHandler_EmptyDatabase(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create in-memory database
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Auto-migrate models
	err = db.AutoMigrate(&models.Log{})
	require.NoError(t, err)

	// Create test request
	req, _ := http.NewRequest("GET", "/api/geolocation", nil)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler := api.GetGeolocationHandler(db)
	handler(c)

	// Assert response
	assert.Equal(t, 200, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	// Should return empty array in data field
	data, ok := response["data"]
	assert.True(t, ok, "Response should have 'data' field")
	if dataArray, ok := data.([]interface{}); ok {
		assert.Equal(t, 0, len(dataArray))
	}
}

// TestGetGeolocationHandler_MultipleCountries tests geolocation with multiple countries
func TestGetGeolocationHandler_MultipleCountries(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create in-memory database
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Auto-migrate models
	err = db.AutoMigrate(&models.Log{})
	require.NoError(t, err)

	// Insert test logs with various countries
	testLogs := []models.Log{
		{ClientIP: "192.168.1.1", ThreatType: "XSS", Country: "United States"},
		{ClientIP: "192.168.1.2", ThreatType: "SQLi", Country: "United States"},
		{ClientIP: "192.168.1.3", ThreatType: "RCE", Country: "United States"},
		{ClientIP: "10.0.0.1", ThreatType: "XSS", Country: "United Kingdom"},
		{ClientIP: "10.0.0.2", ThreatType: "XSS", Country: "United Kingdom"},
		{ClientIP: "172.16.0.1", ThreatType: "LFI", Country: "Germany"},
		{ClientIP: "172.16.0.2", ThreatType: "XSS", Country: "France"},
		{ClientIP: "172.16.0.3", ThreatType: "SQLi", Country: "France"},
	}

	for _, log := range testLogs {
		err := db.Create(&log).Error
		require.NoError(t, err)
	}

	// Create test request
	req, _ := http.NewRequest("GET", "/api/geolocation", nil)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler := api.GetGeolocationHandler(db)
	handler(c)

	// Assert response
	assert.Equal(t, 200, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	// Verify geolocation data
	data, ok := response["data"]
	assert.True(t, ok, "Response should have 'data' field")
	dataArray, ok := data.([]interface{})
	assert.True(t, ok, "Data should be an array")

	// Note: The actual number of countries may vary based on GeoIP service availability
	// With MaxMind or fallback services, private IPs may all map to "Unknown"
	assert.GreaterOrEqual(t, len(dataArray), 1, "Should have at least 1 country grouping")

	// Create a map to verify country counts
	totalCount := 0.0
	for _, item := range dataArray {
		itemMap, ok := item.(map[string]interface{})
		assert.True(t, ok)
		country, ok := itemMap["country"].(string)
		assert.True(t, ok)
		assert.NotEmpty(t, country, "Country should not be empty")
		count, ok := itemMap["count"].(float64)
		assert.True(t, ok)
		totalCount += count
	}

	// Verify total count matches number of logs created (8)
	assert.Equal(t, 8.0, totalCount, "Total count should match number of logs")
}

// TestGetGeolocationHandler_UnknownCountries tests with IPs that have no geolocation
func TestGetGeolocationHandler_UnknownCountries(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create in-memory database
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Auto-migrate models
	err = db.AutoMigrate(&models.Log{})
	require.NoError(t, err)

	// Insert test logs with unknown/private IPs
	testLogs := []models.Log{
		{ClientIP: "127.0.0.1", ThreatType: "XSS", Country: ""},
		{ClientIP: "192.168.1.1", ThreatType: "SQLi", Country: ""},
		{ClientIP: "10.0.0.1", ThreatType: "RCE", Country: ""},
	}

	for _, log := range testLogs {
		err := db.Create(&log).Error
		require.NoError(t, err)
	}

	// Create test request
	req, _ := http.NewRequest("GET", "/api/geolocation", nil)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler := api.GetGeolocationHandler(db)
	handler(c)

	// Assert response
	assert.Equal(t, 200, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	// Should return data (may be grouped under "Unknown" or similar)
	data, ok := response["data"]
	assert.True(t, ok, "Response should have 'data' field")
	dataArray, ok := data.([]interface{})
	assert.True(t, ok, "Data should be an array")
	assert.GreaterOrEqual(t, len(dataArray), 1, "Should have at least one geolocation entry")
}

// TestNewWAFChallengeVerifyHandler_InvalidJSON tests with malformed JSON
func TestNewWAFChallengeVerifyHandler_InvalidJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	handler := api.NewWAFChallengeVerifyHandler(db)

	// Create test request with invalid JSON
	req, _ := http.NewRequest("POST", "/api/waf/challenge/verify", bytes.NewBufferString("{invalid json"))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert error response
	assert.Equal(t, 400, w.Code)
}

// TestNewWAFChallengeVerifyHandler_MissingChallengeID tests with missing challenge_id
func TestNewWAFChallengeVerifyHandler_MissingChallengeID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	handler := api.NewWAFChallengeVerifyHandler(db)

	// Create test request without required challenge_id field (using form data)
	req, _ := http.NewRequest("POST", "/api/waf/challenge/verify", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert error response
	assert.Equal(t, 400, w.Code)
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "INVALID_REQUEST", resp["code"])
}

// TestSetStatsDB tests setting the stats database
func TestSetStatsDB(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Should not panic
	assert.NotPanics(t, func() {
		api.SetStatsDB(db)
	})
}

// TestNewWAFEventHandler_WithCFConnectingIP tests IP extraction with CF-Connecting-IP header
func TestNewWAFEventHandler_WithCFConnectingIP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create in-memory database and initialize TI service
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	api.InitTIService(db)

	mockLogRepo := new(MockLogRepository)
	mockAuditLogRepo := new(MockAuditLogRepository)
	mockRuleRepo := new(MockRuleRepository)
	mockBlocklistRepo := new(MockBlocklistRepository)

	logService := service.NewLogService(mockLogRepo)
	auditLogService := service.NewAuditLogService(mockAuditLogRepo)
	ruleService := service.NewRuleService(mockRuleRepo)
	blocklistService := service.NewBlocklistService(mockBlocklistRepo, mockLogRepo)

	// Mock rule lookup
	mockRuleRepo.On("FindAll", mock.Anything).Return([]models.Rule{}, nil).Once()

	// Mock log creation - should use CF-Connecting-IP value
	mockLogRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.Log")).
		Run(func(args mock.Arguments) {
			log := args.Get(1).(*models.Log)
			assert.Equal(t, "104.16.0.1", log.ClientIP, "Should use CF-Connecting-IP header value")
		}).Return(nil).Once()

	handler := api.NewWAFEventHandler(logService, auditLogService, ruleService, blocklistService)

	// Create test request with CF-Connecting-IP header
	event := websocket.WAFEvent{
		IP:      "10.0.0.1",
		Threat:  "XSS",
		Method:  "GET",
		Path:    "/test",
		Blocked: false,
	}
	jsonData, _ := json.Marshal(event)

	req, _ := http.NewRequest("POST", "/api/waf/event", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("CF-Connecting-IP", "104.16.0.1") // Cloudflare header

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert response
	assert.Equal(t, 200, w.Code)

	// Verify mock expectations
	mockRuleRepo.AssertExpectations(t)
	mockLogRepo.AssertExpectations(t)
}

// TestNewWAFEventHandler_WithXRealIP tests IP extraction with X-Real-IP header
func TestNewWAFEventHandler_WithXRealIP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create in-memory database and initialize TI service
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	api.InitTIService(db)

	mockLogRepo := new(MockLogRepository)
	mockAuditLogRepo := new(MockAuditLogRepository)
	mockRuleRepo := new(MockRuleRepository)
	mockBlocklistRepo := new(MockBlocklistRepository)

	logService := service.NewLogService(mockLogRepo)
	auditLogService := service.NewAuditLogService(mockAuditLogRepo)
	ruleService := service.NewRuleService(mockRuleRepo)
	blocklistService := service.NewBlocklistService(mockBlocklistRepo, mockLogRepo)

	// Mock rule lookup
	mockRuleRepo.On("FindAll", mock.Anything).Return([]models.Rule{}, nil).Once()

	// Mock log creation - should use X-Real-IP value
	mockLogRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.Log")).
		Run(func(args mock.Arguments) {
			log := args.Get(1).(*models.Log)
			assert.Equal(t, "172.16.0.1", log.ClientIP, "Should use X-Real-IP header value")
		}).Return(nil).Once()

	handler := api.NewWAFEventHandler(logService, auditLogService, ruleService, blocklistService)

	// Create test request with X-Real-IP header
	event := websocket.WAFEvent{
		IP:      "10.0.0.1",
		Threat:  "XSS",
		Method:  "GET",
		Path:    "/test",
		Blocked: false,
	}
	jsonData, _ := json.Marshal(event)

	req, _ := http.NewRequest("POST", "/api/waf/event", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Real-IP", "172.16.0.1") // Nginx/Apache header

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert response
	assert.Equal(t, 200, w.Code)

	// Verify mock expectations
	mockRuleRepo.AssertExpectations(t)
	mockLogRepo.AssertExpectations(t)
}

// TestNewWAFEventHandler_WithXClientIP tests IP extraction with X-Client-IP header
func TestNewWAFEventHandler_WithXClientIP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create in-memory database and initialize TI service
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	api.InitTIService(db)

	mockLogRepo := new(MockLogRepository)
	mockAuditLogRepo := new(MockAuditLogRepository)
	mockRuleRepo := new(MockRuleRepository)
	mockBlocklistRepo := new(MockBlocklistRepository)

	logService := service.NewLogService(mockLogRepo)
	auditLogService := service.NewAuditLogService(mockAuditLogRepo)
	ruleService := service.NewRuleService(mockRuleRepo)
	blocklistService := service.NewBlocklistService(mockBlocklistRepo, mockLogRepo)

	// Mock rule lookup
	mockRuleRepo.On("FindAll", mock.Anything).Return([]models.Rule{}, nil).Once()

	// Mock log creation - should use X-Client-IP value
	mockLogRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.Log")).
		Run(func(args mock.Arguments) {
			log := args.Get(1).(*models.Log)
			assert.Equal(t, "192.0.2.1", log.ClientIP, "Should use X-Client-IP header value")
		}).Return(nil).Once()

	handler := api.NewWAFEventHandler(logService, auditLogService, ruleService, blocklistService)

	// Create test request with X-Client-IP header
	event := websocket.WAFEvent{
		IP:      "10.0.0.1",
		Threat:  "XSS",
		Method:  "GET",
		Path:    "/test",
		Blocked: false,
	}
	jsonData, _ := json.Marshal(event)

	req, _ := http.NewRequest("POST", "/api/waf/event", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Client-IP", "192.0.2.1") // Generic proxy header

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert response
	assert.Equal(t, 200, w.Code)

	// Verify mock expectations
	mockRuleRepo.AssertExpectations(t)
	mockLogRepo.AssertExpectations(t)
}

// TestNewWAFEventHandler_NoHeaderPriority tests that X-Public-IP has highest priority
func TestNewWAFEventHandler_NoHeaderPriority(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create in-memory database and initialize TI service
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	api.InitTIService(db)

	mockLogRepo := new(MockLogRepository)
	mockAuditLogRepo := new(MockAuditLogRepository)
	mockRuleRepo := new(MockRuleRepository)
	mockBlocklistRepo := new(MockBlocklistRepository)

	logService := service.NewLogService(mockLogRepo)
	auditLogService := service.NewAuditLogService(mockAuditLogRepo)
	ruleService := service.NewRuleService(mockRuleRepo)
	blocklistService := service.NewBlocklistService(mockBlocklistRepo, mockLogRepo)

	// Mock rule lookup
	mockRuleRepo.On("FindAll", mock.Anything).Return([]models.Rule{}, nil).Once()

	// Mock log creation - should use X-Public-IP even though others are present
	mockLogRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.Log")).
		Run(func(args mock.Arguments) {
			log := args.Get(1).(*models.Log)
			assert.Equal(t, "1.2.3.4", log.ClientIP, "Should use X-Public-IP with highest priority")
		}).Return(nil).Once()

	handler := api.NewWAFEventHandler(logService, auditLogService, ruleService, blocklistService)

	// Create test request with multiple headers (X-Public-IP should win)
	event := websocket.WAFEvent{
		IP:      "10.0.0.1",
		Threat:  "XSS",
		Method:  "GET",
		Path:    "/test",
		Blocked: false,
	}
	jsonData, _ := json.Marshal(event)

	req, _ := http.NewRequest("POST", "/api/waf/event", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Public-IP", "1.2.3.4")          // Highest priority
	req.Header.Set("X-Forwarded-For", "5.6.7.8")       // Should be ignored
	req.Header.Set("CF-Connecting-IP", "9.10.11.12")   // Should be ignored
	req.Header.Set("X-Real-IP", "13.14.15.16")         // Should be ignored
	req.Header.Set("X-Client-IP", "17.18.19.20")       // Should be ignored

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert response
	assert.Equal(t, 200, w.Code)

	// Verify mock expectations
	mockRuleRepo.AssertExpectations(t)
	mockLogRepo.AssertExpectations(t)
}

// TestNewWAFEventHandler_FindRuleByName tests finding rule by name fallback
func TestNewWAFEventHandler_FindRuleByName(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create in-memory database and initialize TI service
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	api.InitTIService(db)

	mockLogRepo := new(MockLogRepository)
	mockAuditLogRepo := new(MockAuditLogRepository)
	mockRuleRepo := new(MockRuleRepository)
	mockBlocklistRepo := new(MockBlocklistRepository)

	logService := service.NewLogService(mockLogRepo)
	auditLogService := service.NewAuditLogService(mockAuditLogRepo)
	ruleService := service.NewRuleService(mockRuleRepo)
	blocklistService := service.NewBlocklistService(mockBlocklistRepo, mockLogRepo)

	// Mock rule lookup - rule has Name matching threat but Type doesn't match
	mockRuleRepo.On("FindAll", mock.Anything).Return([]models.Rule{
		{
			ID:       1,
			Name:     "CustomThreat", // This matches the threat name
			Type:     "CUSTOM",       // This doesn't match
			Pattern:  "test",
			Severity: "Critical",
			Enabled:  true,
		},
	}, nil).Once()

	// Mock log creation
	mockLogRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.Log")).
		Run(func(args mock.Arguments) {
			log := args.Get(1).(*models.Log)
			assert.Equal(t, "Critical", log.Severity, "Should use severity from rule found by name")
		}).Return(nil).Once()

	handler := api.NewWAFEventHandler(logService, auditLogService, ruleService, blocklistService)

	// Create test request with threat name matching rule name (not type)
	event := websocket.WAFEvent{
		IP:      "192.168.1.100",
		Threat:  "CustomThreat", // Matches rule Name
		Method:  "GET",
		Path:    "/test",
		Blocked: false,
	}
	jsonData, _ := json.Marshal(event)

	req, _ := http.NewRequest("POST", "/api/waf/event", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert response
	assert.Equal(t, 200, w.Code)

	// Verify mock expectations
	mockRuleRepo.AssertExpectations(t)
	mockLogRepo.AssertExpectations(t)
}

// TestNewWAFChallengeVerifyHandler_Success tests successful challenge verification
func TestNewWAFChallengeVerifyHandler_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create in-memory database
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Auto-migrate AuditLog model
	err = db.AutoMigrate(&models.AuditLog{})
	require.NoError(t, err)

	handler := api.NewWAFChallengeVerifyHandler(db)

	// Create test request with form data
	formData := "challenge_id=test-challenge-123&original_request=/api/test&captcha_token=test-token-value"
	req, _ := http.NewRequest("POST", "/api/waf/challenge/verify", bytes.NewBufferString(formData))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert response - should return HTML
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "Verification Successful")

	// Verify audit log was created
	var auditLog models.AuditLog
	err = db.First(&auditLog).Error
	require.NoError(t, err)
	assert.Equal(t, "CHALLENGE_VERIFICATION", auditLog.Action)
	assert.Equal(t, "SECURITY", auditLog.Category)
	assert.Equal(t, "success", auditLog.Status)
}

// TestNewWAFChallengeVerifyHandler_LongToken tests with long captcha token (>20 chars)
func TestNewWAFChallengeVerifyHandler_LongToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create in-memory database
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Auto-migrate AuditLog model
	err = db.AutoMigrate(&models.AuditLog{})
	require.NoError(t, err)

	handler := api.NewWAFChallengeVerifyHandler(db)

	// Create test request with very long token
	longToken := "this_is_a_very_long_token_that_exceeds_twenty_characters_for_testing_preview_truncation"
	formData := "challenge_id=test-challenge-456&captcha_token=" + longToken
	req, _ := http.NewRequest("POST", "/api/waf/challenge/verify", bytes.NewBufferString(formData))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert response
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "Verification Successful")
}

// TestNewWAFChallengeVerifyHandler_NoToken tests without captcha token
func TestNewWAFChallengeVerifyHandler_NoToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create in-memory database
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Auto-migrate AuditLog model
	err = db.AutoMigrate(&models.AuditLog{})
	require.NoError(t, err)

	handler := api.NewWAFChallengeVerifyHandler(db)

	// Create test request without captcha token
	formData := "challenge_id=test-challenge-789"
	req, _ := http.NewRequest("POST", "/api/waf/challenge/verify", bytes.NewBufferString(formData))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert response
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "Verification Successful")
}

// TestNewWAFChallengeVerifyHandler_WithValidToken tests challenge verification with valid Turnstile token
func TestNewWAFChallengeVerifyHandler_WithValidToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create mock Turnstile server that returns success
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Verify request body
		body, _ := io.ReadAll(r.Body)
		var req map[string]string
		json.Unmarshal(body, &req)
		assert.Equal(t, "test-secret-key", req["secret"])
		assert.Equal(t, "valid-token-123", req["response"])

		// Return success response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":      true,
			"challenge_ts": "2024-01-01T00:00:00Z",
			"hostname":     "example.com",
		})
	}))
	defer mockServer.Close()

	// Override Turnstile URL and HTTP client
	originalURL := api.GetTurnstileVerifyURL()
	originalClient := api.GetHTTPClient()
	defer func() {
		api.SetTurnstileVerifyURL(originalURL)
		api.SetHTTPClient(originalClient)
	}()

	api.SetTurnstileVerifyURL(mockServer.URL)
	api.SetHTTPClient(mockServer.Client())

	// Set environment variable
	os.Setenv("TURNSTILE_SECRET_KEY", "test-secret-key")
	defer os.Unsetenv("TURNSTILE_SECRET_KEY")

	// Create in-memory database
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	err = db.AutoMigrate(&models.AuditLog{})
	require.NoError(t, err)

	handler := api.NewWAFChallengeVerifyHandler(db)

	// Create test request with valid token
	formData := "challenge_id=test-challenge-456&captcha_token=valid-token-123"
	req, _ := http.NewRequest("POST", "/api/waf/challenge/verify", bytes.NewBufferString(formData))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert response
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "Verification Successful")

	// Verify audit log was created
	var auditLog models.AuditLog
	err = db.First(&auditLog).Error
	assert.NoError(t, err)
	assert.Equal(t, "CHALLENGE_VERIFICATION", auditLog.Action)
}

// TestNewWAFChallengeVerifyHandler_WithInvalidToken tests with token that fails verification
func TestNewWAFChallengeVerifyHandler_WithInvalidToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create mock Turnstile server that returns failure
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return failure response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":     false,
			"error-codes": []string{"invalid-input-response"},
		})
	}))
	defer mockServer.Close()

	// Override Turnstile URL and HTTP client
	originalURL := api.GetTurnstileVerifyURL()
	originalClient := api.GetHTTPClient()
	defer func() {
		api.SetTurnstileVerifyURL(originalURL)
		api.SetHTTPClient(originalClient)
	}()

	api.SetTurnstileVerifyURL(mockServer.URL)
	api.SetHTTPClient(mockServer.Client())

	// Set environment variable
	os.Setenv("TURNSTILE_SECRET_KEY", "test-secret-key")
	defer os.Unsetenv("TURNSTILE_SECRET_KEY")

	// Create in-memory database
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	err = db.AutoMigrate(&models.AuditLog{})
	require.NoError(t, err)

	handler := api.NewWAFChallengeVerifyHandler(db)

	// Create test request with invalid token
	formData := "challenge_id=test-challenge-789&captcha_token=invalid-token-999"
	req, _ := http.NewRequest("POST", "/api/waf/challenge/verify", bytes.NewBufferString(formData))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert response - still returns 200 but verification failed
	assert.Equal(t, 200, w.Code)
	assert.Contains(t, w.Body.String(), "Verification Successful")
}

// TestNewWAFChallengeVerifyHandler_TurnstileInvalidJSON tests with invalid JSON response from Turnstile
func TestNewWAFChallengeVerifyHandler_TurnstileInvalidJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create mock server that returns invalid JSON
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{invalid json"))
	}))
	defer mockServer.Close()

	// Override Turnstile URL and HTTP client
	originalURL := api.GetTurnstileVerifyURL()
	originalClient := api.GetHTTPClient()
	defer func() {
		api.SetTurnstileVerifyURL(originalURL)
		api.SetHTTPClient(originalClient)
	}()

	api.SetTurnstileVerifyURL(mockServer.URL)
	api.SetHTTPClient(mockServer.Client())

	// Set environment variable
	os.Setenv("TURNSTILE_SECRET_KEY", "test-secret-key")
	defer os.Unsetenv("TURNSTILE_SECRET_KEY")

	// Create in-memory database
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	err = db.AutoMigrate(&models.AuditLog{})
	require.NoError(t, err)

	handler := api.NewWAFChallengeVerifyHandler(db)

	// Create test request
	formData := "challenge_id=test-challenge-999&captcha_token=test-token"
	req, _ := http.NewRequest("POST", "/api/waf/challenge/verify", bytes.NewBufferString(formData))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert response
	assert.Equal(t, 200, w.Code)
}

// TestNewWAFChallengeVerifyHandler_TurnstileHTTPError tests with HTTP error from Turnstile
func TestNewWAFChallengeVerifyHandler_TurnstileHTTPError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Override Turnstile URL to invalid URL to cause HTTP error
	originalURL := api.GetTurnstileVerifyURL()
	defer api.SetTurnstileVerifyURL(originalURL)

	api.SetTurnstileVerifyURL("http://invalid-url-that-does-not-exist.local:99999")

	// Set environment variable
	os.Setenv("TURNSTILE_SECRET_KEY", "test-secret-key")
	defer os.Unsetenv("TURNSTILE_SECRET_KEY")

	// Create in-memory database
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	err = db.AutoMigrate(&models.AuditLog{})
	require.NoError(t, err)

	handler := api.NewWAFChallengeVerifyHandler(db)

	// Create test request
	formData := "challenge_id=test-challenge-error&captcha_token=test-token"
	req, _ := http.NewRequest("POST", "/api/waf/challenge/verify", bytes.NewBufferString(formData))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Execute handler
	handler(c)

	// Assert response
	assert.Equal(t, 200, w.Code)
}
