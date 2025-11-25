package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/database/models"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/geoip"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/logger"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/service"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/threatintel"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/websocket"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type WAFStats struct {
	ThreatsDetected int                  `json:"threats_detected"`
	RequestsBlocked int                  `json:"requests_blocked"`
	TotalRequests   int                  `json:"total_requests"`
	LastSeen        string               `json:"last_seen"`
	Recent          []websocket.WAFEvent `json:"recent"`
}

var (
	statsMu sync.RWMutex
	stats   = WAFStats{
		Recent: make([]websocket.WAFEvent, 0, 5),
	}
	// Threat intelligence enrichment service
	tiService *threatintel.EnrichmentService
)

// InitTIService initializes the threat intelligence service with database connection
func InitTIService(db *gorm.DB) {
	tiService = threatintel.NewEnrichmentService()
	tiService.SetDB(db)

	// Set VirusTotal API key from environment variable
	virusTotalKey := os.Getenv("VIRUSTOTAL_API_KEY")
	if virusTotalKey != "" {
		tiService.SetVirusTotalKey(virusTotalKey)
		logger.Log.Info("VirusTotal API key configured")
	} else {
		logger.Log.Warn("VIRUSTOTAL_API_KEY not set. VirusTotal enrichment will be skipped. Get a free API key from https://www.virustotal.com/")
	}

	// Set AbuseIPDB API key from environment variable
	abuseIPDBKey := os.Getenv("ABUSEIPDB_API_KEY")
	if abuseIPDBKey != "" {
		tiService.SetAbuseIPDBKey(abuseIPDBKey)
		logger.Log.Info("AbuseIPDB API key configured")
	} else {
		logger.Log.Warn("ABUSEIPDB_API_KEY not set. AbuseIPDB enrichment will be skipped. Get a free API key from https://www.abuseipdb.com/")
	}

	if virusTotalKey == "" && abuseIPDBKey == "" {
		logger.Log.Warn("No TI API keys configured. Using only GeoIP enrichment.")
	}
}

// extractRealClientIP extracts the real client IP from proxy headers
// Checks in order of priority:
// 1. X-Public-IP: Client self-reported public IP (Tailscale/VPN)
// 2. X-Forwarded-For: Comma-separated proxy chain (takes first)
// 3. CF-Connecting-IP: Cloudflare header
// 4. X-Real-IP: Nginx/Apache proxy header
// 5. X-Client-IP: Generic proxy header
// Returns empty string if no header found
func extractRealClientIP(c *gin.Context) (string, string, bool) {
	// X-Public-IP: Client self-reported public IP (Tailscale/VPN client)
	// Highest priority - means client explicitly sent their public IP
	if xPublicIP := c.GetHeader("X-Public-IP"); xPublicIP != "" {
		xPublicIP = strings.TrimSpace(xPublicIP)
		if xPublicIP != "" {
			logger.Log.WithField("ip", xPublicIP).Debug("X-Public-IP header found (Tailscale/VPN)")
			return xPublicIP, xPublicIP, true // Return: IP, publicIP, isXPublicIP
		}
	}

	// X-Forwarded-For: 203.0.113.45, 198.51.100.10 (comma-separated, first is client)
	if xForwardedFor := c.GetHeader("X-Forwarded-For"); xForwardedFor != "" {
		// Take the first IP (the actual client)
		ips := strings.Split(xForwardedFor, ",")
		if len(ips) > 0 {
			realIP := strings.TrimSpace(ips[0])
			if realIP != "" {
				logger.Log.WithField("header", xForwardedFor).Debug("X-Forwarded-For header found")
				return realIP, "", false // Return: IP, publicIP (empty), isXPublicIP (false)
			}
		}
	}

	// CF-Connecting-IP: Cloudflare header
	if cfIP := c.GetHeader("CF-Connecting-IP"); cfIP != "" {
		cfIP = strings.TrimSpace(cfIP)
		if cfIP != "" {
			logger.Log.WithField("ip", cfIP).Debug("CF-Connecting-IP header found")
			return cfIP, "", false
		}
	}

	// X-Real-IP: Nginx, Apache proxy header
	if xRealIP := c.GetHeader("X-Real-IP"); xRealIP != "" {
		xRealIP = strings.TrimSpace(xRealIP)
		if xRealIP != "" {
			logger.Log.WithField("ip", xRealIP).Debug("X-Real-IP header found")
			return xRealIP, "", false
		}
	}

	// X-Client-IP: Generic proxy header
	if xClientIP := c.GetHeader("X-Client-IP"); xClientIP != "" {
		xClientIP = strings.TrimSpace(xClientIP)
		if xClientIP != "" {
			logger.Log.WithField("ip", xClientIP).Debug("X-Client-IP header found")
			return xClientIP, "", false
		}
	}

	return "", "", false // Return empty strings and false if no header found
}

// GetSeverityFromThreatType determines severity level based on threat type
func GetSeverityFromThreatType(threatType string) string {
	severityMap := map[string]string{
		// Critical threats - can lead to complete system compromise
		"SQL_INJECTION":           "Critical",
		"COMMAND_INJECTION":       "Critical",
		"XXE":                     "Critical",
		"LDAP_INJECTION":          "Critical",
		"RFI":                     "Critical",
		"SSTI":                    "Critical",

		// High threats - can lead to significant data exposure or unauthorized access
		"XSS":                     "High",
		"LFI":                     "High",
		"PATH_TRAVERSAL":          "High",
		"SSRF":                    "High",
		"NOSQL_INJECTION":         "High",
		"HTTP_RESPONSE_SPLITTING": "High",

		// Medium threats - restricted access or partial compromise
		"PROTOTYPE_POLLUTION": "Medium",
	}

	if severity, exists := severityMap[threatType]; exists {
		return severity
	}
	return "Medium" // Default severity for unknown threats
}

// getRuleByThreatName retrieves a rule from database by threat type
// The WAF sends threat.Type which corresponds to rule.Type (e.g., "XSS", "SQL_INJECTION")
func getRuleByThreatName(ruleService *service.RuleService, threatType string) *models.Rule {
	ctx := context.Background()

	allRules, err := ruleService.GetAllRules(ctx)
	if err != nil {
		logger.Log.WithError(err).Warn("Failed to fetch rules from database")
		return nil
	}

	// Search by Type first (primary match - what WAF sends)
	for _, rule := range allRules {
		if rule.Type == threatType {
			return &rule
		}
	}

	// Fallback: search by Name or Description
	for _, rule := range allRules {
		if rule.Name == threatType || rule.Description == threatType {
			return &rule
		}
	}

	logger.Log.WithField("threat_type", threatType).Warn("No rule found in database for threat type")
	return nil
}

// NewWAFEventHandler creates a handler for WAF events with dependency injection
func NewWAFEventHandler(logService *service.LogService, auditLogService *service.AuditLogService, ruleService *service.RuleService, blocklistService *service.BlocklistService) gin.HandlerFunc {
	return func(c *gin.Context) {
		var event websocket.WAFEvent
		if !ValidateJSON(c, &event) {
			logger.Log.Error("Failed to bind JSON")
			return
		}

		// Extract real client IP from proxy headers if available
		realIP, publicIP, isXPublicIP := extractRealClientIP(c)
		if realIP != event.IP && realIP != "" {
			logger.Log.WithFields(map[string]interface{}{
				"real_ip":      realIP,
				"waf_reported": event.IP,
			}).Info("Real client IP detected from headers")
			event.IP = realIP
		}

		logger.Log.WithFields(map[string]interface{}{
			"ip":     event.IP,
			"threat": event.Threat,
			"method": event.Method,
			"path":   event.Path,
		}).Info("Received WAF event")
		if isXPublicIP && publicIP != "" {
			logger.Log.WithField("public_ip", publicIP).Info("X-Public-IP (Tailscale/VPN client public IP)")
		}

		event.Timestamp = time.Now().Format("2006-01-02T15:04:05Z07:00")
		logger.Log.WithFields(map[string]interface{}{
			"blocked_by": event.BlockedBy,
			"threat":     event.Threat,
			"blocked":    event.Blocked,
		}).Info("Received event with BlockedBy status")

		ctx := c.Request.Context()

		// Fetch rule from database to get severity and payload
		ruleFromDB := getRuleByThreatName(ruleService, event.Threat)
		severity := "Medium" // Default
		payload := ""        // Default empty

		if ruleFromDB != nil {
			severity = ruleFromDB.Severity
			payload = ruleFromDB.Pattern // Pattern from rule
			logger.Log.WithFields(map[string]interface{}{
				"name":           ruleFromDB.Name,
				"severity":       severity,
				"payload_length": len(payload),
			}).Debug("Found rule in DB")
		} else {
			logger.Log.WithField("threat", event.Threat).Debug("No rule found in DB, using default severity")
		}

		// Update in-memory stats
		statsMu.Lock()
	// ThreatsDetected = only detected threats (not blocked)
	if !event.Blocked {
		stats.ThreatsDetected++
	}
	// RequestsBlocked = only blocked threats
	if event.Blocked {
		stats.RequestsBlocked++
	}
	// TotalRequests = detected + blocked (all security events)
	stats.TotalRequests++
		stats.LastSeen = time.Now().Format("15:04:05")

		if len(stats.Recent) >= 5 {
			stats.Recent = stats.Recent[1:]
		}
		stats.Recent = append(stats.Recent, event)
		statsMu.Unlock()

		// Create log model with severity and payload from database rule
		log := models.Log{
			ThreatType:        event.Threat,
			Description:       event.Description,
			ClientIP:          event.IP,
			Method:            event.Method,
			URL:               event.Path,
			UserAgent:         event.UA,
			Payload:           payload,
			CreatedAt:         time.Now(),
			Blocked:           event.Blocked,
			BlockedBy:         event.BlockedBy,
			Severity:          severity,
			ClientIPSource:    event.IPSource,
			ClientIPTrusted:   event.IPTrusted,
			ClientIPVPNReport: event.IPVPNReport,
			ClientIPPublic:    publicIP,
			IPTrustScore:      event.IPTrustScore,
		}

		if log.ClientIPVPNReport {
			logger.Log.WithFields(map[string]interface{}{
				"internal_ip": log.ClientIP,
				"public_ip":   log.ClientIPPublic,
				"source":      log.ClientIPSource,
				"trusted":     log.ClientIPTrusted,
			}).Info("TAILSCALE/VPN CLIENT DETECTED")
		}

		// Save event using service layer
		if err := logService.CreateLog(ctx, &log); err != nil {
			logger.Log.WithError(err).Error("Failed to save log")
			InternalServerErrorWithCode(c, ErrDatabaseError, "Failed to save event")
			return
		}

		// Enrich log with threat intelligence synchronously
		enrichmentStart := time.Now()
		if err := tiService.EnrichLog(&log); err != nil {
			logger.Log.WithFields(map[string]interface{}{
				"ip": log.ClientIP,
			}).WithError(err).Warn("Threat intelligence enrichment failed")
		} else {
			logger.Log.WithFields(map[string]interface{}{
				"ip":       log.ClientIP,
				"duration": time.Since(enrichmentStart),
			}).Info("Threat intelligence enrichment completed")
		}

		// Update the log with enriched threat intel data
		updateData := map[string]interface{}{
			"enriched_at":     log.EnrichedAt,
			"ip_reputation":   log.IPReputation,
			"is_malicious":    log.IsMalicious,
			"asn":             log.ASN,
			"isp":             log.ISP,
			"country":         log.Country,
			"threat_level":    log.ThreatLevel,
			"threat_source":   log.ThreatSource,
			"is_on_blocklist": log.IsOnBlocklist,
			"blocklist_name":  log.BlocklistName,
			"abuse_reports":   log.AbuseReports,
			"ip_trust_score":  log.IPTrustScore,
		}

		if err := logService.UpdateLogsByIPAndDescription(ctx, log.ClientIP, log.Description, updateData); err != nil {
			logger.Log.WithError(err).Error("Failed to update log with threat intelligence")
		} else {
			logger.Log.Info("Log successfully enriched and updated")
			websocket.BroadcastEnrichment(
				log.ClientIP,
				log.IPReputation,
				log.ThreatLevel,
				log.Country,
				log.ASN,
				log.IsMalicious,
				log.ThreatSource,
				log.AbuseReports,
				log.IsOnBlocklist,
				log.BlocklistName,
			)
		}

		websocket.Broadcast(event)
		c.JSON(200, gin.H{"status": "event_received"})
	}
}

// Iniezione della dipendenza del database
var statsDB *gorm.DB

// SetStatsDB imposta il database per il gestore delle statistiche
func SetStatsDB(db *gorm.DB) {
	statsDB = db
}

func WAFStatsHandler(c *gin.Context) {
	// Se il database è disponibile, carica i dati dal database invece che dalla memoria
	if statsDB != nil {
		var detectedLogs int64     // Threats detected but not blocked (blocked = false)
		var blockedLogs int64      // Threats blocked (blocked = true)
		var totalLogs int64        // Total = detected + blocked

		// Conta i logs detected (not blocked)
		statsDB.Model(&models.Log{}).Where("blocked = ?", false).Count(&detectedLogs)

		// Conta i logs bloccati
		statsDB.Model(&models.Log{}).Where("blocked = ?", true).Count(&blockedLogs)

		// Total = detected + blocked
		totalLogs = detectedLogs + blockedLogs

		// Carica i log recenti
		var recentLogs []models.Log
		statsDB.Order("created_at DESC").Limit(5).Find(&recentLogs)

		// Converti i log recenti a WAFEvent
		recentEvents := make([]websocket.WAFEvent, 0, len(recentLogs))
		for _, log := range recentLogs {
			recentEvents = append(recentEvents, websocket.WAFEvent{
				IP:           log.ClientIP,
				Threat:       log.ThreatType,
				Payload:      log.Payload,
				Blocked:      log.Blocked,
				BlockedBy:    log.BlockedBy,
				Timestamp:    log.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
				Method:       log.Method,
				Path:         log.URL,
				UA:           log.UserAgent,
				IPReputation: log.IPReputation,
				Country:      log.Country,
				ASN:          log.ASN,
				IPTrustScore: log.IPTrustScore,
			})
		}

		c.JSON(200, WAFStats{
			ThreatsDetected: int(detectedLogs),  // Only detected (not blocked)
			RequestsBlocked: int(blockedLogs),   // Only blocked
			TotalRequests:   int(totalLogs),     // Detected + Blocked
			LastSeen:        fmt.Sprintf("%d minuti fa", 0),
			Recent:          recentEvents,
		})
		return
	}

	// Fallback: usa i dati in memoria se il database non è disponibile
	statsMu.RLock()
	defer statsMu.RUnlock()
	c.JSON(200, stats)
}

// verifyTurnstileToken verifies a Cloudflare Turnstile token
func verifyTurnstileToken(token string) bool {
	// Get Turnstile secret key from environment
	secretKey := os.Getenv("TURNSTILE_SECRET_KEY")
	if secretKey == "" {
		logger.Log.Warn("TURNSTILE_SECRET_KEY not set in environment")
		return false
	}

	// Prepare request to Cloudflare Turnstile verification API
	verifyURL := "https://challenges.cloudflare.com/turnstile/v0/siteverify"

	// Create request body
	requestBody := map[string]string{
		"secret":   secretKey,
		"response": token,
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		logger.Log.WithError(err).Error("Failed to marshal Turnstile request")
		return false
	}

	// Make request to Cloudflare
	resp, err := http.Post(verifyURL, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		logger.Log.WithError(err).Error("Failed to verify Turnstile token")
		return false
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Log.WithError(err).Error("Failed to read Turnstile response")
		return false
	}

	// Parse response
	var verifyResponse struct {
		Success     bool     `json:"success"`
		ChallengeTS string   `json:"challenge_ts"`
		Hostname    string   `json:"hostname"`
		ErrorCodes  []string `json:"error-codes"`
	}

	if err := json.Unmarshal(body, &verifyResponse); err != nil {
		logger.Log.WithError(err).Error("Failed to parse Turnstile response")
		return false
	}

	// Check if verification was successful
	if !verifyResponse.Success {
		logger.Log.WithField("error_codes", verifyResponse.ErrorCodes).Warn("Turnstile verification failed")
		return false
	}

	logger.Log.Info("Turnstile verified successfully")
	return true
}

// GeolocationData represents geolocation statistics
type GeolocationData struct {
	Country string `json:"country"`
	Count   int    `json:"count"`
}

// GetGeolocationHandler returns geolocation distribution of threats
func GetGeolocationHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		geoService, err := geoip.GetInstance()
		if err != nil {
			logger.Log.WithError(err).Error("Failed to initialize GeoIP service")
			InternalServerErrorWithCode(c, ErrServiceError, "GeoIP service unavailable")
			return
		}

		var logs []models.Log
		result := db.Find(&logs)
		if result.Error != nil {
			logger.Log.WithError(result.Error).Error("Failed to fetch logs")
			InternalServerErrorWithCode(c, ErrDatabaseError, "Database error")
			return
		}

		// Group logs by country with IP enrichment fallback
		countryMap := make(map[string]int)
		for _, log := range logs {
			country := geoService.LookupCountryWithEnrichment(log.ClientIP)
			countryMap[country]++
		}

		// Convert to response format
		var response []GeolocationData
		for country, count := range countryMap {
			response = append(response, GeolocationData{
				Country: country,
				Count:   count,
			})
		}

		c.JSON(200, gin.H{
			"data": response,
		})
	}
}

// NewWAFChallengeVerifyHandler handles CAPTCHA challenge verification
func NewWAFChallengeVerifyHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var request struct {
			ChallengeID     string `form:"challenge_id" binding:"required"`
			OriginalRequest string `form:"original_request"`
			CaptchaToken    string `form:"captcha_token"`
		}

		if err := c.ShouldBind(&request); err != nil {
			logger.Log.WithError(err).Error("Failed to bind challenge verify request")
			BadRequestWithCode(c, ErrInvalidRequest, "Invalid request")
			return
		}

		tokenPreview := request.CaptchaToken
		if len(tokenPreview) > 20 {
			tokenPreview = tokenPreview[:20] + "..."
		}
		logger.Log.WithFields(map[string]interface{}{
			"challenge_id":      request.ChallengeID,
			"original_request":  request.OriginalRequest,
			"captcha_token":     tokenPreview,
			"captcha_token_len": len(request.CaptchaToken),
		}).Info("Challenge verification request received")

		// Verify the Turnstile token with Cloudflare
		captchaVerified := false
		if request.CaptchaToken != "" {
			logger.Log.Info("Verifying Turnstile token with Cloudflare")
			captchaVerified = verifyTurnstileToken(request.CaptchaToken)
			if captchaVerified {
				logger.Log.Info("Turnstile verification SUCCESS")
			} else {
				logger.Log.Warn("Turnstile verification FAILED")
			}
		} else {
			logger.Log.Warn("No Captcha token provided")
		}

		// Log the successful challenge verification
		auditLog := models.AuditLog{
			UserID:      0, // System action
			Action:      "CHALLENGE_VERIFICATION",
			Category:    "SECURITY",
			Status:      "success",
			Description: fmt.Sprintf("Challenge verified: %s", request.ChallengeID),
			IPAddress:   c.ClientIP(),
		}
		if err := db.Create(&auditLog).Error; err != nil {
			logger.Log.WithError(err).Error("Failed to log challenge verification")
		}

		// Return success HTML page
		successHTML := `<!DOCTYPE html>
<html>
<head>
    <title>Verification Successful</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: #111827;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            color: #f3f4f6;
        }
        .container {
            background: #1f2937;
            border: 1px solid #374151;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
            text-align: center;
            max-width: 500px;
        }
        .icon-box {
            margin-bottom: 20px;
            display: flex;
            justify-content: center;
        }
        .icon-box i {
            font-size: 64px;
            color: #10b981;
        }
        h1 {
            color: #10b981;
            margin-top: 0;
            margin-bottom: 15px;
            font-size: 28px;
        }
        p {
            color: #d1d5db;
            line-height: 1.6;
            margin-bottom: 10px;
        }
        .success-box {
            background: #064e3b;
            border: 1px solid #059669;
            border-left: 4px solid #10b981;
            border-radius: 4px;
            padding: 15px;
            margin: 20px 0;
            color: #a7f3d0;
        }
        .success-box strong { color: #d1fae5; }
        a {
            display: inline-block;
            margin-top: 20px;
            padding: 12px 24px;
            background: #3b82f6;
            color: white;
            text-decoration: none;
            border-radius: 6px;
            font-weight: 600;
            transition: all 0.3s;
        }
        a:hover {
            background: #2563eb;
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
        }
        .info {
            font-size: 12px;
            color: #9ca3af;
            margin-top: 20px;
            padding-top: 15px;
            border-top: 1px solid #374151;
        }
        .info p { margin: 5px 0; }
    </style>
    <script>
        // Redirect after 3 seconds
        setTimeout(function() {
            window.location.href = '/';
        }, 3000);
    </script>
</head>
<body>
    <div class="container">
        <div class="icon-box">
            <i class="fas fa-check-circle"></i>
        </div>
        <h1>Verification Successful</h1>
        <p>Thank you for verifying that you are human.</p>
        <p>You will be redirected in 3 seconds...</p>

        <div class="success-box">
            <strong>Challenge ID:</strong> ` + request.ChallengeID + `
        </div>

        <a href="/">Click here if not redirected</a>

        <div class="info">
            <p>You may now access the application normally.</p>
        </div>
    </div>
</body>
</html>`

		c.Header("Content-Type", "text/html; charset=utf-8")
		c.String(200, successHTML)
	}
}