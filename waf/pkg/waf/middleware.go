package waf

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/PiCas19/waf-siem-advanced-detection/waf/internal/detector"
	"github.com/PiCas19/waf-siem-advanced-detection/waf/internal/logger"
	"github.com/PiCas19/waf-siem-advanced-detection/waf/internal/ipextract"
)

func init() {
	caddy.RegisterModule(Middleware{})
	httpcaddyfile.RegisterHandlerDirective("waf", parseCaddyfile)
}

// RequestFingerprint represents a unique request to deduplicate retries
type RequestFingerprint struct {
	Fingerprint string    // MD5 hash of IP + method + path + threat type + payload
	Timestamp   time.Time // When this request was first seen
}

// BlocklistEntry represents a single blocked IP entry
type BlocklistEntry struct {
	IPAddress   string
	Description string
	Reason      string
	Permanent   bool
	ExpiresAt   *time.Time
}

// WhitelistEntry represents a single whitelisted IP entry
type WhitelistEntry struct {
	IPAddress string
	Reason    string
}

// Middleware implements WAF functionality for Caddy
type Middleware struct {
	RulesFile          string   `json:"rules_file,omitempty"`
	LogFile            string   `json:"log_file,omitempty"`
	BlockMode          bool     `json:"block_mode,omitempty"`
	APIEndpoint        string   `json:"api_endpoint,omitempty"`
	RulesEndpoint      string   `json:"rules_endpoint,omitempty"`      // API endpoint to fetch custom rules
	BlocklistEndpoint  string   `json:"blocklist_endpoint,omitempty"`  // API endpoint to fetch blocklist
	WhitelistEndpoint  string   `json:"whitelist_endpoint,omitempty"`  // API endpoint to fetch whitelist
	TrustedProxies     []string `json:"trusted_proxies,omitempty"`     // List of trusted proxy IPs/CIDR ranges

	// Enterprise-grade IP detection configuration
	EnableHMACSignatureValidation bool   `json:"enable_hmac_signature_validation,omitempty"` // Enable HMAC header validation
	HMACSharedSecret              string `json:"hmac_shared_secret,omitempty"`               // Shared secret for HMAC signing
	TrustedSourcesPolicyEndpoint   string `json:"trusted_sources_endpoint,omitempty"`        // API endpoint to fetch trusted sources policy
	EnableDMZDetection            bool   `json:"enable_dmz_detection,omitempty"`            // Enable DMZ IP detection
	DMZNetworks                   []string `json:"dmz_networks,omitempty"`                   // CIDR ranges for DMZ
	EnableTailscaleDetection      bool   `json:"enable_tailscale_detection,omitempty"`      // Enable Tailscale IP detection
	TailscaleNetworks             []string `json:"tailscale_networks,omitempty"`            // CIDR ranges for Tailscale

	detector       *detector.Detector
	logger         *logger.Logger
	httpClient     *http.Client
	stopRuleReload chan bool // Channel to stop rule reloading goroutine

	// Enterprise: Trusted source management
	trustedSourceManager *ipextract.GlobalTrustedSourceManager
	sourcePolicy        *ipextract.TrustedSourcePolicy
	headerSigConfig     *ipextract.HeaderSignatureConfig
	dmzConfig           *ipextract.DMZDetectionConfig
	tailscaleConfig     *ipextract.TailscaleDetectionConfig

	// Cache for recently processed requests to prevent duplicate logging of retries
	// Key: MD5 fingerprint of (IP + method + path + threat + payload)
	// Value: timestamp when this request was first processed
	// Deduplicates within 3 seconds window (typical browser retry timeout)
	processedRequests     map[string]time.Time
	processedRequestsLock sync.RWMutex

	// Blocklist/Whitelist caching for performance
	// We cache these to avoid database hits on every request
	blocklist           map[string][]BlocklistEntry // Key: IP address, Value: list of block entries
	blocklistLock       sync.RWMutex
	blocklistLastUpdate time.Time

	whitelist           map[string]bool // Key: IP address, Value: true if whitelisted
	whitelistLock       sync.RWMutex
	whitelistLastUpdate time.Time

	stopListReload chan bool // Channel to stop list reloading goroutine
}

// CaddyModule returns the Caddy module information
func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.waf",
		New: func() caddy.Module { return new(Middleware) },
	}
}

// Provision sets up the middleware
func (m *Middleware) Provision(ctx caddy.Context) error {
	// Initialize detector
	m.detector = detector.NewDetector()

	// Initialize logger
	if m.LogFile != "" {
		l, err := logger.NewLogger(m.LogFile)
		if err != nil {
			return fmt.Errorf("failed to initialize logger: %v", err)
		}
		m.logger = l
	}

	// Configure trusted proxies for IP extraction
	if len(m.TrustedProxies) > 0 {
		ipextract.SetTrustedProxies(m.TrustedProxies)
	}

	// Initialize HTTP client for sending events to API
	m.httpClient = &http.Client{
		Timeout: 5 * time.Second,
	}

	// Initialize enterprise-grade IP detection
	m.trustedSourceManager = ipextract.NewGlobalTrustedSourceManager()
	m.sourcePolicy = ipextract.CreateDefaultPolicy()
	m.trustedSourceManager.AddPolicy(m.sourcePolicy)

	// Configure HMAC signature validation
	m.headerSigConfig = ipextract.DefaultHeaderSignatureConfig()
	if m.EnableHMACSignatureValidation && m.HMACSharedSecret != "" {
		m.headerSigConfig.Enabled = true
		m.headerSigConfig.SharedSecret = m.HMACSharedSecret
		m.headerSigConfig.RequireSignature = true
	}

	// Configure DMZ detection
	m.dmzConfig = &ipextract.DMZDetectionConfig{
		Enabled:     m.EnableDMZDetection,
		DMZNetworks: m.DMZNetworks,
	}

	// Configure Tailscale detection
	m.tailscaleConfig = &ipextract.TailscaleDetectionConfig{
		Enabled:               m.EnableTailscaleDetection,
		TailscaleNetworks:     m.TailscaleNetworks,
		VerifyHeaderSignature: m.EnableHMACSignatureValidation,
	}
	if m.TailscaleNetworks == nil || len(m.TailscaleNetworks) == 0 {
		// Use default Tailscale network if not specified
		m.tailscaleConfig.TailscaleNetworks = []string{"100.64.0.0/10"}
	}

	// Initialize processed requests cache
	m.processedRequests = make(map[string]time.Time)

	// Initialize blocklist/whitelist caches
	m.blocklist = make(map[string][]BlocklistEntry)
	m.whitelist = make(map[string]bool)

	// Load initial custom rules from API endpoint
	if m.RulesEndpoint != "" {
		if err := m.loadCustomRulesFromAPI(); err != nil {
			// Don't fail if custom rules can't be loaded, WAF should still work with default rules
		}

		// Start background goroutine to periodically reload rules from API
		m.stopRuleReload = make(chan bool, 1)
		go m.reloadRulesBackground()
	}

	// Load initial blocklist/whitelist from API endpoint
	if m.APIEndpoint != "" {
		if err := m.loadBlocklistFromAPI(); err != nil {
			// Silent fail - WAF continues with empty blocklist
		}
		if err := m.loadWhitelistFromAPI(); err != nil {
			// Silent fail - WAF continues with empty whitelist
		}

		// Start background goroutine to periodically reload blocklist/whitelist from API
		m.stopListReload = make(chan bool, 1)
		go m.reloadListsBackground()
	}

	return nil
}

// loadCustomRulesFromAPI fetches custom rules from the API endpoint and updates the detector
func (m *Middleware) loadCustomRulesFromAPI() error {
	if m.RulesEndpoint == "" {
		return nil
	}

	// Fetch rules from API
	resp, err := m.httpClient.Get(m.RulesEndpoint)
	if err != nil {
		return fmt.Errorf("failed to fetch rules from API: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	// Define Rule struct inline to avoid circular imports
	type Rule struct {
		ID               uint   `json:"id"`
		Name             string `json:"name"`
		Pattern          string `json:"pattern"`
		Type             string `json:"type"`
		Severity         string `json:"severity"`
		Enabled          bool   `json:"enabled"`
		Action           string `json:"action"`
		BlockEnabled     bool   `json:"block_enabled"`
		DropEnabled      bool   `json:"drop_enabled"`
		RedirectEnabled  bool   `json:"redirect_enabled"`
		ChallengeEnabled bool   `json:"challenge_enabled"`
		RedirectURL      string `json:"redirect_url"`
	}

	type APIResponse struct {
		Rules []Rule `json:"rules"`
		Count int    `json:"count"`
	}

	var apiResponse APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
		return fmt.Errorf("failed to decode API response: %v", err)
	}

	// Convert to detector CustomRule format
	customRules := make([]*detector.CustomRule, 0)
	for _, rule := range apiResponse.Rules {
		customRules = append(customRules, &detector.CustomRule{
			ID:               rule.ID,
			Name:             rule.Name,
			Pattern:          rule.Pattern,
			Type:             rule.Type,
			Severity:         rule.Severity,
			Enabled:          rule.Enabled,
			Action:           rule.Action,
			BlockEnabled:     rule.BlockEnabled,
			DropEnabled:      rule.DropEnabled,
			RedirectEnabled:  rule.RedirectEnabled,
			ChallengeEnabled: rule.ChallengeEnabled,
			RedirectURL:      rule.RedirectURL,
		})
	}

	// Update detector with custom rules
	if err := m.detector.UpdateCustomRules(customRules); err != nil {
		return fmt.Errorf("failed to update custom rules in detector: %v", err)
	}

	return nil
}

// reloadRulesBackground periodically reloads custom rules from API
func (m *Middleware) reloadRulesBackground() {
	ticker := time.NewTicker(60 * time.Second) // Reload every 60 seconds
	defer ticker.Stop()

	for {
		select {
		case <-m.stopRuleReload:
			return
		case <-ticker.C:
			_ = m.loadCustomRulesFromAPI() // Ignore errors, continue operation
		}
	}
}

// computeRequestFingerprint creates a unique fingerprint for a request
// to detect retries of the same malicious request
// Fingerprint = MD5(IP + method + path + threat_type + payload)
func (m *Middleware) computeRequestFingerprint(clientIP string, method string, path string, threatType string, payload string) string {
	// Create a unique identifier for this request
	uniqueStr := fmt.Sprintf("%s|%s|%s|%s|%s", clientIP, method, path, threatType, payload)
	hash := md5.Sum([]byte(uniqueStr))
	return fmt.Sprintf("%x", hash)
}

// isAlreadyProcessed checks if a request (by fingerprint) was already processed recently
// Returns true if same request was seen within last 3 seconds (typical retry window)
func (m *Middleware) isAlreadyProcessed(fingerprint string) bool {
	m.processedRequestsLock.RLock()
	defer m.processedRequestsLock.RUnlock()

	if timestamp, exists := m.processedRequests[fingerprint]; exists {
		// Check if it was seen within last 3 seconds
		if time.Since(timestamp) < 3*time.Second {
			return true
		}
	}
	return false
}

// markAsProcessed marks a request as processed and cleans up old entries
func (m *Middleware) markAsProcessed(fingerprint string) {
	m.processedRequestsLock.Lock()
	defer m.processedRequestsLock.Unlock()

	m.processedRequests[fingerprint] = time.Now()

	// Clean up old entries (older than 5 seconds) to prevent memory bloat
	now := time.Now()
	for fp, timestamp := range m.processedRequests {
		if now.Sub(timestamp) > 5*time.Second {
			delete(m.processedRequests, fp)
		}
	}
}

// ServeHTTP implements the middleware handler
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Use enterprise-grade IP detection with policy validation
	enhancedIPInfo := ipextract.ExtractClientIPWithPolicy(
		r,
		r.RemoteAddr,
		m.trustedSourceManager,
		m.headerSigConfig,
		m.dmzConfig,
		m.tailscaleConfig,
	)

	clientIP := enhancedIPInfo.IP

	// FIRST: Check whitelist - if whitelisted, skip all checks and allow request
	if m.isIPWhitelisted(clientIP) {
		return next.ServeHTTP(w, r)
	}

	// SECOND: Check blocklist - if blocked, handle immediately
	if m.isIPBlocked(clientIP) {
		// IP is on the blocklist, block it
		w.Header().Set("X-WAF-Blocked", "true")
		w.Header().Set("X-WAF-Threat", "IP_BLOCKLIST")
		w.Header().Set("X-WAF-Severity", "critical")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)

		response := fmt.Sprintf(`{
			"error": "Request blocked by WAF",
			"threat_type": "IP_BLOCKLIST",
			"severity": "critical",
			"description": "This IP address has been blocked"
		}`)

		w.Write([]byte(response))
		return nil
	}

	// THIRD: Inspect the request for threats
	threat := m.detector.Inspect(r)

	if threat != nil {
		// Create a fingerprint of this request to detect retries
		// Fingerprint = MD5(IP + method + path + threat_type) - WITHOUT payload
		// This prevents duplicate logging when same threat type is detected in multiple request parameters
		fingerprint := m.computeRequestFingerprint(clientIP, r.Method, r.URL.Path, threat.Type, "")

		// Check if we've already processed this exact request recently (within 3 seconds)
		// This prevents logging the same attack multiple times when browser retries
		if !m.isAlreadyProcessed(fingerprint) {
			// Mark this request as processed
			m.markAsProcessed(fingerprint)

			// Determine if we should block/handle the request based on threat and configuration
			// 1. Default rules always block (IsDefault: true) - use block action
			// 2. Custom rules: check their Action field ("block" or "log")
			// 3. Global block mode blocks everything

			shouldHandle := false
			if threat.IsDefault || m.BlockMode {
				// Default rules and global block mode always trigger blocking
				shouldHandle = true
				// For default rules, default to "block" action if not specified
				if threat.BlockAction == "" {
					threat.BlockAction = "block"
				}
			} else if threat.Action == "block" {
				// Custom rules only trigger blocking if action is "block"
				shouldHandle = true
			}

			// Log the threat with detailed IP source information AND blocking status
			if m.logger != nil {
				blockedBy := ""
				if shouldHandle {
					blockedBy = "auto" // Blocked by WAF rule (default or custom with action="block")
				}

				entry := logger.LogEntry{
					ThreatType:        threat.Type,
					Severity:          threat.Severity,
					Description:       threat.Description,
					ClientIP:          threat.ClientIP,
					ClientIPSource:    string(threat.ClientIPSource),
					ClientIPTrusted:   threat.ClientIPTrusted,
					ClientIPVPNReport: threat.ClientIPVPNReport,
					Method:            r.Method,
					URL:               r.URL.String(),
					UserAgent:         r.UserAgent(),
					Payload:           threat.Payload,
					Blocked:           shouldHandle,  // Whether the request is blocked
					BlockedBy:         blockedBy,     // How it was blocked ("auto" or "")
				}
				m.logger.Log(entry)
			}

			// Send event to API backend with enhanced IP info
			if m.APIEndpoint != "" {
				go m.sendEventToAPI(r, clientIP, threat, enhancedIPInfo)
			}

			// Execute the blocking action if needed
			if shouldHandle {
				// Execute the blocking action (block, drop, redirect, challenge, none)
				return m.executeBlockingAction(w, r, threat)
			}
		}
	}

	// Continue to next handler
	return next.ServeHTTP(w, r)
}

// executeBlockingAction handles the specified blocking action for detected threats
func (m *Middleware) executeBlockingAction(w http.ResponseWriter, r *http.Request, threat *detector.Threat) error {
	// Determine which action to execute
	switch threat.BlockAction {
	case "drop":
		return m.handleDropAction(w, r, threat)
	case "redirect":
		return m.handleRedirectAction(w, r, threat)
	case "challenge":
		return m.handleChallengeAction(w, r, threat)
	case "none":
		// Only log, no blocking - shouldn't reach here but handle it
		return nil
	case "block":
		return m.handleBlockAction(w, r, threat)
	default:
		// Default to block if unknown action
		return m.handleBlockAction(w, r, threat)
	}
}

// handleBlockAction returns HTTP 403 Forbidden
func (m *Middleware) handleBlockAction(w http.ResponseWriter, r *http.Request, threat *detector.Threat) error {
	w.Header().Set("X-WAF-Blocked", "true")
	w.Header().Set("X-WAF-Threat", threat.Type)
	w.Header().Set("X-WAF-Severity", threat.Severity)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)

	response := fmt.Sprintf(`{
		"error": "Request blocked by WAF",
		"threat_type": "%s",
		"severity": "%s",
		"description": "%s"
	}`, threat.Type, threat.Severity, threat.Description)

	w.Write([]byte(response))
	return nil
}

// handleDropAction closes the connection immediately without response
func (m *Middleware) handleDropAction(w http.ResponseWriter, r *http.Request, threat *detector.Threat) error {
	// Try to hijack the connection and close it
	if hijacker, ok := w.(http.Hijacker); ok {
		conn, _, err := hijacker.Hijack()
		if err != nil {
			// Fallback to block if hijacking fails
			return m.handleBlockAction(w, r, threat)
		}
		// Close the connection without sending any response
		conn.Close()
		return nil
	}
	// If hijacking not available, fall back to block
	return m.handleBlockAction(w, r, threat)
}

// handleRedirectAction returns HTTP 302 with Location header
func (m *Middleware) handleRedirectAction(w http.ResponseWriter, r *http.Request, threat *detector.Threat) error {
	w.Header().Set("X-WAF-Blocked", "true")
	w.Header().Set("X-WAF-Threat", threat.Type)
	w.Header().Set("X-WAF-Severity", threat.Severity)
	w.Header().Set("X-Original-URL", r.RequestURI)

	// Use configured redirect URL or fall back to block if not set
	if threat.RedirectURL != "" {
		http.Redirect(w, r, threat.RedirectURL, http.StatusFound) // 302
		return nil
	}
	// No redirect URL configured, fall back to block
	return m.handleBlockAction(w, r, threat)
}

// handleChallengeAction returns HTTP 403 with CAPTCHA challenge HTML
func (m *Middleware) handleChallengeAction(w http.ResponseWriter, r *http.Request, threat *detector.Threat) error {
	w.Header().Set("X-WAF-Blocked", "true")
	w.Header().Set("X-WAF-Threat", threat.Type)
	w.Header().Set("X-WAF-Severity", threat.Severity)
	w.Header().Set("X-WAF-Challenge", "captcha-required")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Generate a challenge ID
	challengeID := fmt.Sprintf("%d", time.Now().UnixNano())

	// Get Turnstile site key from environment
	turnstileSiteKey := os.Getenv("TURNSTILE_SITE_KEY")
	if turnstileSiteKey == "" {
		fmt.Printf("[WARN] TURNSTILE_SITE_KEY not set in environment\n")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Configuration error: Turnstile not configured"))
		return nil
	}

	// Return CAPTCHA challenge HTML (matching dashboard theme) with Cloudflare Turnstile
	challengeHTML := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Security Challenge</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
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
            font-size: 48px;
            color: #60a5fa;
        }
        h1 {
            color: #60a5fa;
            margin-top: 0;
            margin-bottom: 15px;
            font-size: 28px;
        }
        p {
            color: #d1d5db;
            line-height: 1.6;
            margin-bottom: 10px;
        }
        .threat-box {
            background: #374151;
            border: 1px solid #4b5563;
            border-left: 4px solid #ef4444;
            border-radius: 4px;
            padding: 15px;
            margin: 20px 0;
            color: #fca5a5;
            text-align: left;
        }
        .threat-box strong { color: #fecaca; }
        .challenge-box {
            background: #111827;
            border: 1px solid #374151;
            border-radius: 4px;
            padding: 20px;
            margin: 20px 0;
        }
        .challenge-id {
            font-family: 'Courier New', monospace;
            font-size: 12px;
            color: #60a5fa;
            background: #1f2937;
            padding: 8px 12px;
            border-radius: 4px;
            word-break: break-all;
            margin: 10px 0;
        }
        .turnstile-container {
            display: flex;
            justify-content: center;
            margin: 20px 0;
        }
        button {
            background: #3b82f6;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            margin-top: 15px;
            transition: all 0.3s;
        }
        button:hover {
            background: #2563eb;
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
        }
        button:active {
            transform: scale(0.98);
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
</head>
<body>
    <div class="container">
        <div class="icon-box">
            <i class="fas fa-lock"></i>
        </div>
        <h1>Security Verification Required</h1>
        <p>We've detected suspicious activity on your request.</p>
        <p>Please verify you're human to continue.</p>

        <div class="threat-box">
            <strong>Threat Detected:</strong> %s
        </div>

        <div class="challenge-box">
            <p style="color: #d1d5db; margin-bottom: 15px;">Verifying you are human...</p>

            <form id="challengeForm" method="POST" action="/api/waf/challenge/verify">
                <input type="hidden" name="challenge_id" value="%s">
                <input type="hidden" name="original_request" value="%s">
                <input type="hidden" id="turnstile-token" name="captcha_token">

                <div class="turnstile-container">
                    <div class="cf-turnstile" data-sitekey="%s" data-callback="onTurnstileSuccess" data-theme="dark"></div>
                </div>

                <button type="submit" id="submitBtn">Verify and Continue</button>
            </form>
        </div>

        <div class="info">
            <p>If you believe this is an error, please contact support.</p>
            <p>Your IP: <code style="color: #60a5fa;">%s</code></p>
        </div>
    </div>

    <script>
        function onTurnstileSuccess(token) {
            // Store the token from Turnstile
            document.getElementById('turnstile-token').value = token;
        }

        // Verify form on submit
        document.getElementById('challengeForm').addEventListener('submit', function(e) {
            var token = document.getElementById('turnstile-token').value;
            if (!token) {
                e.preventDefault();
                alert('Please complete the Turnstile verification');
                return false;
            }
        });
    </script>
</body>
</html>`, turnstileSiteKey, threat.Type, challengeID, r.RequestURI, getClientIP(r))

	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(challengeHTML))
	return nil
}

// blockRequest returns a 403 Forbidden response (deprecated, kept for compatibility)
func (m *Middleware) blockRequest(w http.ResponseWriter, threat *detector.Threat) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)

	response := fmt.Sprintf(`{
		"error": "Request blocked by WAF",
		"threat_type": "%s",
		"severity": "%s",
		"description": "%s"
	}`, threat.Type, threat.Severity, threat.Description)

	w.Write([]byte(response))
	return nil
}

// sendEventToAPI sends a threat event to the backend API
func (m *Middleware) sendEventToAPI(r *http.Request, clientIP string, threat *detector.Threat, enhancedIPInfo *ipextract.EnhancedClientIPInfo) {
	// Determine if the request is actually blocked:
	// 1. Default rules always block (IsDefault: true)
	// 2. Custom rules block if action is "block"
	// 3. Global block mode blocks everything
	blocked := m.BlockMode || threat.IsDefault
	if !threat.IsDefault {
		// For custom rules, only block if action is "block"
		if threat.Action == "block" {
			blocked = true
		} else {
			// If custom rule action is "log" or other, don't block
			blocked = false
		}
	}

	// Determine blocked_by field for dashboard display
	blockedBy := ""
	if blocked {
		if m.BlockMode || threat.IsDefault {
			blockedBy = "auto" // Blocked by default/global rule
		} else if threat.Action == "block" {
			blockedBy = "auto" // Blocked by custom rule with action "block"
		}
	}

	eventPayload := map[string]interface{}{
		"ip":               clientIP,
		"ip_source":        string(threat.ClientIPSource),    // How the IP was extracted: x-public-ip, x-forwarded-for, x-real-ip, remote-addr
		"ip_trusted":       threat.ClientIPTrusted,           // Whether the IP source is trusted
		"ip_vpn_reported":  threat.ClientIPVPNReport,         // Whether this is a self-reported IP from Tailscale/VPN
		"threat":           threat.Type,
		"description":      threat.Description,               // Rule name/description for per-rule blocking
		"method":           r.Method,
		"path":             r.URL.Path,
		"query":            r.URL.RawQuery,
		"user_agent":       r.UserAgent(),
		"payload":          threat.Payload,
		"timestamp":        time.Now().Format(time.RFC3339),
		"blocked":          blocked,
		"blocked_by":       blockedBy,

		// Enterprise-grade IP detection details
		"ip_source_type":           enhancedIPInfo.SourceType,
		"ip_classification":        enhancedIPInfo.SourceClassification,
		"ip_header_signature_valid": enhancedIPInfo.HeaderSignatureValid,
		"ip_is_dmz":                 enhancedIPInfo.DMZIP,
		"ip_is_tailscale":           enhancedIPInfo.TailscaleIP,
		"ip_trust_score":            enhancedIPInfo.TrustScore,
		"ip_validation_details":     enhancedIPInfo.ValidationDetails,
	}

	jsonData, err := json.Marshal(eventPayload)
	if err != nil {
		return
	}

	req, err := http.NewRequest("POST", m.APIEndpoint+"/waf/event", bytes.NewBuffer(jsonData))
	if err != nil {
		return
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

// getClientIP extracts the real client IP from the request using robust extraction logic
// Priority: X-Public-IP (Tailscale/VPN) > X-Forwarded-For (trusted proxy) > X-Real-IP (trusted proxy) > RemoteAddr
func getClientIP(r *http.Request) string {
	return ipextract.ExtractClientIPSimple(
		r.Header.Get("X-Public-IP"),
		r.Header.Get("X-Forwarded-For"),
		r.Header.Get("X-Real-IP"),
		r.RemoteAddr,
	)
}

// getClientIPInfo extracts detailed client IP information from the request
func getClientIPInfo(r *http.Request) *ipextract.ClientIPInfo {
	return ipextract.ExtractClientIPFromHeaders(
		r.Header.Get("X-Public-IP"),
		r.Header.Get("X-Forwarded-For"),
		r.Header.Get("X-Real-IP"),
		r.RemoteAddr,
	)
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler
func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "rules":
				if !d.Args(&m.RulesFile) {
					return d.ArgErr()
				}
			case "log_file":
				if !d.Args(&m.LogFile) {
					return d.ArgErr()
				}
			case "block_mode":
				var mode string
				if !d.Args(&mode) {
					return d.ArgErr()
				}
				m.BlockMode = mode == "true"
			case "api_endpoint":
				if !d.Args(&m.APIEndpoint) {
					return d.ArgErr()
				}
			case "rules_endpoint":
				if !d.Args(&m.RulesEndpoint) {
					return d.ArgErr()
				}
			case "blocklist_endpoint":
				if !d.Args(&m.BlocklistEndpoint) {
					return d.ArgErr()
				}
			case "whitelist_endpoint":
				if !d.Args(&m.WhitelistEndpoint) {
					return d.ArgErr()
				}
			case "trusted_proxies":
				// Parse multiple trusted proxy IPs/CIDR ranges
				for d.NextArg() {
					m.TrustedProxies = append(m.TrustedProxies, d.Val())
				}
			// Enterprise-grade IP detection
			case "enable_hmac_signature_validation":
				var mode string
				if !d.Args(&mode) {
					return d.ArgErr()
				}
				m.EnableHMACSignatureValidation = mode == "true"
			case "hmac_shared_secret":
				if !d.Args(&m.HMACSharedSecret) {
					return d.ArgErr()
				}
			case "trusted_sources_endpoint":
				if !d.Args(&m.TrustedSourcesPolicyEndpoint) {
					return d.ArgErr()
				}
			case "enable_dmz_detection":
				var mode string
				if !d.Args(&mode) {
					return d.ArgErr()
				}
				m.EnableDMZDetection = mode == "true"
			case "dmz_networks":
				// Parse multiple DMZ network CIDR ranges
				for d.NextArg() {
					m.DMZNetworks = append(m.DMZNetworks, d.Val())
				}
			case "enable_tailscale_detection":
				var mode string
				if !d.Args(&mode) {
					return d.ArgErr()
				}
				m.EnableTailscaleDetection = mode == "true"
			case "tailscale_networks":
				// Parse multiple Tailscale network CIDR ranges
				for d.NextArg() {
					m.TailscaleNetworks = append(m.TailscaleNetworks, d.Val())
				}
			default:
				return d.Errf("unknown subdirective: %s", d.Val())
			}
		}
	}
	return nil
}

// parseCaddyfile parses the Caddyfile configuration
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Middleware
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return &m, err
}

// loadBlocklistFromAPI fetches the blocklist from the API endpoint and updates the cache
func (m *Middleware) loadBlocklistFromAPI() error {
	if m.BlocklistEndpoint == "" {
		return nil
	}

	resp, err := m.httpClient.Get(m.BlocklistEndpoint)
	if err != nil {
		return fmt.Errorf("failed to fetch blocklist from API: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var data struct {
		BlockedIPs []BlocklistEntry `json:"blocked_ips"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return fmt.Errorf("failed to decode blocklist response: %v", err)
	}

	// Build new cache (map by IP)
	newCache := make(map[string][]BlocklistEntry)
	for _, entry := range data.BlockedIPs {
		// Skip expired entries
		if !entry.Permanent && entry.ExpiresAt != nil && entry.ExpiresAt.Before(time.Now()) {
			continue
		}
		newCache[entry.IPAddress] = append(newCache[entry.IPAddress], entry)
	}

	// Update cache
	m.blocklistLock.Lock()
	m.blocklist = newCache
	m.blocklistLastUpdate = time.Now()
	m.blocklistLock.Unlock()

	return nil
}

// loadWhitelistFromAPI fetches the whitelist from the API endpoint and updates the cache
func (m *Middleware) loadWhitelistFromAPI() error {
	if m.WhitelistEndpoint == "" {
		return nil
	}

	resp, err := m.httpClient.Get(m.WhitelistEndpoint)
	if err != nil {
		return fmt.Errorf("failed to fetch whitelist from API: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var data struct {
		WhitelistedIPs []WhitelistEntry `json:"whitelisted_ips"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return fmt.Errorf("failed to decode whitelist response: %v", err)
	}

	// Build new cache (set by IP)
	newCache := make(map[string]bool)
	for _, entry := range data.WhitelistedIPs {
		newCache[entry.IPAddress] = true
	}

	// Update cache
	m.whitelistLock.Lock()
	m.whitelist = newCache
	m.whitelistLastUpdate = time.Now()
	m.whitelistLock.Unlock()

	return nil
}

// reloadListsBackground periodically reloads blocklist/whitelist from API
func (m *Middleware) reloadListsBackground() {
	ticker := time.NewTicker(30 * time.Second) // Reload every 30 seconds
	defer ticker.Stop()

	for {
		select {
		case <-m.stopListReload:
			return
		case <-ticker.C:
			_ = m.loadBlocklistFromAPI()   // Ignore errors, continue operation
			_ = m.loadWhitelistFromAPI()   // Ignore errors, continue operation
		}
	}
}

// isIPWhitelisted checks if an IP is in the whitelist cache
func (m *Middleware) isIPWhitelisted(ip string) bool {
	m.whitelistLock.RLock()
	defer m.whitelistLock.RUnlock()
	return m.whitelist[ip]
}

// isIPBlocked checks if an IP is in the blocklist cache
// Returns true if IP is blocked, false otherwise
func (m *Middleware) isIPBlocked(ip string) bool {
	m.blocklistLock.RLock()
	defer m.blocklistLock.RUnlock()
	_, exists := m.blocklist[ip]
	return exists
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)