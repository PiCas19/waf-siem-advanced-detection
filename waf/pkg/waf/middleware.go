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
	RulesFile  string `json:"rules_file,omitempty"`
	LogFile    string `json:"log_file,omitempty"`
	BlockMode  bool   `json:"block_mode,omitempty"`
	APIEndpoint string `json:"api_endpoint,omitempty"`

	detector *detector.Detector
	logger   *logger.Logger
	httpClient *http.Client
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

	return nil
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
			go m.sendEventToAPI(clientIP, threat)
		}

		// Block request if in block mode
		if m.BlockMode {
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
func (m *Middleware) sendEventToAPI(clientIP string, threat *detector.Threat) {
	eventPayload := map[string]interface{}{
		"ip":        clientIP,
		"type":      threat.Type,
		"payload":   threat.Payload,
		"timestamp": time.Now().Format(time.RFC3339),
	}

	jsonData, err := json.Marshal(eventPayload)
	if err != nil {
		fmt.Printf("Error marshaling event: %v\n", err)
		return
	}

	req, err := http.NewRequest("POST", m.APIEndpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		fmt.Printf("Error sending event to API: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("API returned non-OK status: %d\n", resp.StatusCode)
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