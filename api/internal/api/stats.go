package api

import (
	"bytes"
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
			fmt.Printf("[DEBUG] X-Public-IP header found (Tailscale/VPN): %s\n", xPublicIP)
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
				fmt.Printf("[DEBUG] X-Forwarded-For header found: %s\n", xForwardedFor)
				return realIP, "", false // Return: IP, publicIP (empty), isXPublicIP (false)
			}
		}
	}

	// CF-Connecting-IP: Cloudflare header
	if cfIP := c.GetHeader("CF-Connecting-IP"); cfIP != "" {
		cfIP = strings.TrimSpace(cfIP)
		if cfIP != "" {
			fmt.Printf("[DEBUG] CF-Connecting-IP header found: %s\n", cfIP)
			return cfIP, "", false
		}
	}

	// X-Real-IP: Nginx, Apache proxy header
	if xRealIP := c.GetHeader("X-Real-IP"); xRealIP != "" {
		xRealIP = strings.TrimSpace(xRealIP)
		if xRealIP != "" {
			fmt.Printf("[DEBUG] X-Real-IP header found: %s\n", xRealIP)
			return xRealIP, "", false
		}
	}

	// X-Client-IP: Generic proxy header
	if xClientIP := c.GetHeader("X-Client-IP"); xClientIP != "" {
		xClientIP = strings.TrimSpace(xClientIP)
		if xClientIP != "" {
			fmt.Printf("[DEBUG] X-Client-IP header found: %s\n", xClientIP)
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

func NewWAFEventHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var event websocket.WAFEvent
		if err := c.ShouldBindJSON(&event); err != nil {
			fmt.Printf("[ERROR] Failed to bind JSON: %v\n", err)
			fmt.Printf("[ERROR] Request body: %v\n", c.Request.Body)
			c.JSON(400, gin.H{"error": "invalid json"})
			return
		}

		// Extract real client IP from proxy headers if available
		// Also extracts the public IP if this is from a Tailscale/VPN client (X-Public-IP header)
		realIP, publicIP, isXPublicIP := extractRealClientIP(c)
		if realIP != event.IP && realIP != "" {
			fmt.Printf("[INFO] Real client IP detected from headers: %s (WAF reported: %s)\n", realIP, event.IP)
			// Update event IP to the real one
			event.IP = realIP
		}

		fmt.Printf("[INFO] Received WAF event: IP=%s, Threat=%s, Method=%s, Path=%s\n", event.IP, event.Threat, event.Method, event.Path)
		if isXPublicIP && publicIP != "" {
			fmt.Printf("[INFO] X-Public-IP (Tailscale/VPN client public IP): %s\n", publicIP)
		}

		event.Timestamp = time.Now().Format("2006-01-02T15:04:05Z07:00")

		// Use BlockedBy from WAF event (it already comes set)
		fmt.Printf("[INFO] Received event with BlockedBy=%s for threat=%s (blocked=%v)\n", event.BlockedBy, event.Threat, event.Blocked)

		statsMu.Lock()
		stats.ThreatsDetected++
		if event.Blocked {
			stats.RequestsBlocked++
		}
		stats.TotalRequests++
		stats.LastSeen = time.Now().Format("15:04:05")

		fmt.Printf("[INFO] Stats updated: Threats=%d, Blocked=%d, Total=%d (Blocked=%v)\n", stats.ThreatsDetected, stats.RequestsBlocked, stats.TotalRequests, event.Blocked)

		if len(stats.Recent) >= 5 {
			stats.Recent = stats.Recent[1:]
		}
		stats.Recent = append(stats.Recent, event)
		statsMu.Unlock()

		// Save event to database
		log := models.Log{
			ThreatType:  event.Threat,
			Description: event.Description, // Rule name/description for per-rule blocking
			ClientIP:    event.IP,
			Method:      event.Method,
			URL:         event.Path,
			UserAgent:   event.UA,
			Payload:     event.Payload,
			CreatedAt:   time.Now(),
			Blocked:     event.Blocked,
			BlockedBy:   event.BlockedBy,
			Severity:    GetSeverityFromThreatType(event.Threat),
			// IP source metadata from WAF
			// These fields track how the IP was extracted by the WAF (X-Public-IP, X-Forwarded-For, etc)
			ClientIPSource:    event.IPSource,
			ClientIPTrusted:   event.IPTrusted,
			ClientIPVPNReport: event.IPVPNReport,
			ClientIPPublic:    publicIP, // Store the public IP from X-Public-IP header if available
		IPTrustScore:      event.IPTrustScore, // Store the trust score calculated by WAF
	}

	// Log important IP metadata
	if log.ClientIPVPNReport {
		fmt.Printf("[INFO] *** TAILSCALE/VPN CLIENT DETECTED *** Internal IP=%s, Public IP=%s, Source=%s, Trusted=%v\n",
			log.ClientIP, log.ClientIPPublic, log.ClientIPSource, log.ClientIPTrusted)
	}
	if err := db.Create(&log).Error; err != nil {
		fmt.Printf("[ERROR] Failed to save log to database: %v\n", err)
		c.JSON(500, gin.H{"error": "failed to save event"})
		return
	}

	// Enrich log with threat intelligence synchronously (blocks until enrichment completes or times out)
	enrichmentStart := time.Now()
	if err := tiService.EnrichLog(&log); err != nil {
		fmt.Printf("[WARN] Threat intelligence enrichment failed for IP %s: %v\n", log.ClientIP, err)
	} else {
		fmt.Printf("[INFO] Threat intelligence enrichment completed for IP %s in %v\n", log.ClientIP, time.Since(enrichmentStart))
	}

	// Update the log with enriched threat intel data using explicit field updates
	// This prevents GORM from skipping zero values
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
		"ip_trust_score":  log.IPTrustScore, // Persist the trust score to database
	}
	if err := db.Model(&models.Log{}).Where("id = ?", log.ID).Updates(updateData).Error; err != nil {
		fmt.Printf("[ERROR] Failed to update log %d with threat intelligence: %v\n", log.ID, err)
	} else {
		fmt.Printf("[INFO] Log %d successfully enriched and updated\n", log.ID)
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
		var totalLogs int64
		var blockedLogs int64
		var threatLogs int64

		// Conta tutti i logs
		statsDB.Model(&models.Log{}).Count(&totalLogs)

		// Conta i logs bloccati
		statsDB.Model(&models.Log{}).Where("blocked = ?", true).Count(&blockedLogs)

		// Conta i logs con minacce (tutti sono considerati minacce)
		statsDB.Model(&models.Log{}).Count(&threatLogs)

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
			ThreatsDetected: int(threatLogs),
			RequestsBlocked: int(blockedLogs),
			TotalRequests:   int(totalLogs),
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
	secretKey := os.Getenv("TURNSTILE_SECRET_KEY")
	if secretKey == "" {
		fmt.Printf("[WARN] TURNSTILE_SECRET_KEY not set in environment\n")
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
		fmt.Printf("[ERROR] Failed to marshal Turnstile request: %v\n", err)
		return false
	}

	// Make request to Cloudflare
	resp, err := http.Post(verifyURL, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		fmt.Printf("[ERROR] Failed to verify Turnstile token: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("[ERROR] Failed to read Turnstile response: %v\n", err)
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
		fmt.Printf("[ERROR] Failed to parse Turnstile response: %v\n", err)
		return false
	}

	// Check if verification was successful
	if !verifyResponse.Success {
		fmt.Printf("[WARN] Turnstile verification failed: %v\n", verifyResponse.ErrorCodes)
		return false
	}

	fmt.Printf("[INFO] Turnstile verified successfully\n")
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
			fmt.Printf("[ERROR] Failed to initialize GeoIP service: %v\n", err)
			c.JSON(500, gin.H{"error": "geoip service unavailable"})
			return
		}

		var logs []models.Log
		result := db.Find(&logs)
		if result.Error != nil {
			fmt.Printf("[ERROR] Failed to fetch logs: %v\n", result.Error)
			c.JSON(500, gin.H{"error": "database error"})
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
			fmt.Printf("[ERROR] Failed to bind challenge verify request: %v\n", err)
			c.JSON(400, gin.H{"error": "invalid request"})
			return
		}

		// Verify the Turnstile token with Cloudflare
		captchaVerified := false
		if request.CaptchaToken != "" {
			captchaVerified = verifyTurnstileToken(request.CaptchaToken)
			if !captchaVerified {
				fmt.Printf("[WARN] Turnstile verification failed\n")
			}
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
			fmt.Printf("[ERROR] Failed to log challenge verification: %v\n", err)
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