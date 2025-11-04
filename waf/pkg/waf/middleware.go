package waf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/PiCas19/waf-siem-advanced-detection/waf/internal/detector"
	"github.com/PiCas19/waf-siem-advanced-detection/waf/internal/logger"
)

func init() {
	caddy.RegisterModule(Middleware{})
	httpcaddyfile.RegisterHandlerDirective("waf", parseCaddyfile)
}

// Middleware implements WAF functionality for Caddy
type Middleware struct {
	RulesFile     string `json:"rules_file,omitempty"`
	LogFile       string `json:"log_file,omitempty"`
	BlockMode     bool   `json:"block_mode,omitempty"`
	APIEndpoint   string `json:"api_endpoint,omitempty"`
	RulesEndpoint string `json:"rules_endpoint,omitempty"` // API endpoint to fetch custom rules

	detector       *detector.Detector
	logger         *logger.Logger
	httpClient     *http.Client
	stopRuleReload chan bool // Channel to stop rule reloading goroutine
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

	// Initialize HTTP client for sending events to API
	m.httpClient = &http.Client{
		Timeout: 5 * time.Second,
	}

	// Load initial custom rules from API endpoint
	if m.RulesEndpoint != "" {
		if err := m.loadCustomRulesFromAPI(); err != nil {
			fmt.Printf("[WARN] Failed to load custom rules from API: %v\n", err)
			// Don't fail if custom rules can't be loaded, WAF should still work with default rules
		}

		// Start background goroutine to periodically reload rules from API
		m.stopRuleReload = make(chan bool, 1)
		go m.reloadRulesBackground()
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
		ID          uint   `json:"id"`
		Name        string `json:"name"`
		Pattern     string `json:"pattern"`
		Type        string `json:"type"`
		Severity    string `json:"severity"`
		Enabled     bool   `json:"enabled"`
		Action      string `json:"action"`
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
			ID:       rule.ID,
			Name:     rule.Name,
			Pattern:  rule.Pattern,
			Type:     rule.Type,
			Severity: rule.Severity,
			Enabled:  rule.Enabled,
			Action:   rule.Action,
		})
	}

	// Update detector with custom rules
	if err := m.detector.UpdateCustomRules(customRules); err != nil {
		return fmt.Errorf("failed to update custom rules in detector: %v", err)
	}

	fmt.Printf("[INFO] WAF: Loaded %d custom rules from API\n", len(customRules))
	return nil
}

// reloadRulesBackground periodically reloads custom rules from API
func (m *Middleware) reloadRulesBackground() {
	ticker := time.NewTicker(60 * time.Second) // Reload every 60 seconds
	defer ticker.Stop()

	fmt.Printf("[INFO] WAF: Started background rule reloading from API (every 60 seconds)\n")

	for {
		select {
		case <-m.stopRuleReload:
			fmt.Printf("[INFO] WAF: Stopped background rule reloading\n")
			return
		case <-ticker.C:
			if err := m.loadCustomRulesFromAPI(); err != nil {
				fmt.Printf("[WARN] WAF: Failed to reload custom rules from API: %v\n", err)
			}
		}
	}
}

// ServeHTTP implements the middleware handler
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Inspect the request for threats
	threat := m.detector.Inspect(r)

	if threat != nil {
		clientIP := getClientIP(r)

		// Log the threat
		if m.logger != nil {
			entry := logger.LogEntry{
				ThreatType:  threat.Type,
				Severity:    threat.Severity,
				Description: threat.Description,
				ClientIP:    clientIP,
				Method:      r.Method,
				URL:         r.URL.String(),
				UserAgent:   r.UserAgent(),
				Payload:     threat.Payload,
			}
			m.logger.Log(entry)
		}

		// Send event to API backend
		if m.APIEndpoint != "" {
			go m.sendEventToAPI(r, clientIP, threat)
		}

		// Determine if we should block the request:
		// 1. Default rules always block (IsDefault: true)
		// 2. Custom rules block if action is "block"
		// 3. Global block mode blocks everything
		shouldBlock := m.BlockMode || threat.IsDefault
		if !threat.IsDefault && threat.Action == "block" {
			shouldBlock = true
		}

		if shouldBlock {
			return m.blockRequest(w, threat)
		}
	}

	// Continue to next handler
	return next.ServeHTTP(w, r)
}

// blockRequest returns a 403 Forbidden response
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
func (m *Middleware) sendEventToAPI(r *http.Request, clientIP string, threat *detector.Threat) {
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
		"ip":         clientIP,
		"threat":     threat.Type,
		"method":     r.Method,
		"path":       r.URL.Path,
		"query":      r.URL.RawQuery,
		"user_agent": r.UserAgent(),
		"timestamp":  time.Now().Format(time.RFC3339),
		"blocked":    blocked,
		"blocked_by": blockedBy,
	}

	jsonData, err := json.Marshal(eventPayload)
	if err != nil {
		fmt.Printf("[ERROR] WAF: Error marshaling event: %v\n", err)
		return
	}

	fmt.Printf("[INFO] WAF: Sending event to %s: %s\n", m.APIEndpoint, string(jsonData))

	req, err := http.NewRequest("POST", m.APIEndpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("[ERROR] WAF: Error creating request: %v\n", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		fmt.Printf("[ERROR] WAF: Error sending event to API: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("[ERROR] WAF: API returned non-OK status: %d\n", resp.StatusCode)
	} else {
		fmt.Printf("[INFO] WAF: Event sent successfully (HTTP %d)\n", resp.StatusCode)
	}
}

// getClientIP extracts the real client IP from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fallback to RemoteAddr
	ip := strings.Split(r.RemoteAddr, ":")[0]
	return ip
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

// Interface guards
var (
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)