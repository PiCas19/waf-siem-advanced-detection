package waf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/waf/internal/detector"
	"github.com/PiCas19/waf-siem-advanced-detection/waf/internal/logger"
)

type WAFHandler struct {
	detector     *detector.Detector
	logger       *logger.Logger
	apiEndpoint  string // URL to send events to API
	httpClient   *http.Client
}

func NewWAFHandler(logPath string) (*WAFHandler, error) {
	l, err := logger.NewLogger(logPath)
	if err != nil {
		return nil, err
	}

	// Get API endpoint from environment or use default
	apiEndpoint := os.Getenv("API_ENDPOINT")
	if apiEndpoint == "" {
		apiEndpoint = "http://localhost:8080" // Default for local development
	}

	return &WAFHandler{
		detector:    detector.NewDetector(),
		logger:      l,
		apiEndpoint: apiEndpoint,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}, nil
}

func (h *WAFHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	threat := h.detector.Inspect(r)
	if threat != nil {
		// Create event with all necessary fields
		event := map[string]interface{}{
			"ip":           r.RemoteAddr,
			"method":       r.Method,
			"path":         r.RequestURI,
			"query":        r.URL.RawQuery,
			"user_agent":   r.Header.Get("User-Agent"),
			"threat":       threat.Type,
			"payload":      threat.Payload,
			"timestamp":    time.Now().Format(time.RFC3339),
			"blocked":      true,
			"block_action": threat.BlockAction,
		}

		// Log locally
		h.logger.LogJSON(event)

		// Send to API endpoint asynchronously (non-blocking)
		go h.sendEventToAPI(event)

		// Execute blocking action based on configuration
		h.executeBlockingAction(w, r, threat)
		return
	}
}

// executeBlockingAction handles the specified blocking action for detected threats
func (h *WAFHandler) executeBlockingAction(w http.ResponseWriter, r *http.Request, threat *detector.Threat) {
	// Determine which action to execute
	switch threat.BlockAction {
	case "drop":
		h.handleDropAction(w, r, threat)
	case "redirect":
		h.handleRedirectAction(w, r, threat)
	case "challenge":
		h.handleChallengeAction(w, r, threat)
	case "none":
		// Only log, no blocking
		h.handleNoneAction(w, r, threat)
	case "block":
		h.handleBlockAction(w, r, threat)
	default:
		// Default to block if unknown action
		h.handleBlockAction(w, r, threat)
	}
}

// handleBlockAction returns HTTP 403 Forbidden
func (h *WAFHandler) handleBlockAction(w http.ResponseWriter, r *http.Request, threat *detector.Threat) {
	w.Header().Set("X-WAF-Blocked", "true")
	w.Header().Set("X-WAF-Threat", threat.Type)
	w.Header().Set("X-WAF-Severity", threat.Severity)
	http.Error(w, "Forbidden - Request blocked by WAF", http.StatusForbidden)
}

// handleDropAction closes the connection immediately without response
func (h *WAFHandler) handleDropAction(w http.ResponseWriter, r *http.Request, threat *detector.Threat) {
	// Try to hijack the connection and close it
	if hijacker, ok := w.(http.Hijacker); ok {
		conn, _, err := hijacker.Hijack()
		if err != nil {
			// Fallback to block if hijacking fails
			h.handleBlockAction(w, r, threat)
			return
		}
		// Close the connection without sending any response
		conn.Close()
	} else {
		// If hijacking not available, fall back to block
		h.handleBlockAction(w, r, threat)
	}
}

// handleRedirectAction returns HTTP 302 with Location header
func (h *WAFHandler) handleRedirectAction(w http.ResponseWriter, r *http.Request, threat *detector.Threat) {
	w.Header().Set("X-WAF-Blocked", "true")
	w.Header().Set("X-WAF-Threat", threat.Type)
	w.Header().Set("X-WAF-Severity", threat.Severity)
	w.Header().Set("X-Original-URL", r.RequestURI)

	// Use configured redirect URL or fall back to block if not set
	if threat.RedirectURL != "" {
		http.Redirect(w, r, threat.RedirectURL, http.StatusFound) // 302
	} else {
		// No redirect URL configured, fall back to block
		h.handleBlockAction(w, r, threat)
	}
}

// handleChallengeAction returns HTTP 403 with CAPTCHA challenge HTML
func (h *WAFHandler) handleChallengeAction(w http.ResponseWriter, r *http.Request, threat *detector.Threat) {
	w.Header().Set("X-WAF-Blocked", "true")
	w.Header().Set("X-WAF-Threat", threat.Type)
	w.Header().Set("X-WAF-Severity", threat.Severity)
	w.Header().Set("X-WAF-Challenge", "captcha-required")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Generate a challenge ID
	challengeID := fmt.Sprintf("%d", time.Now().UnixNano())

	// Return CAPTCHA challenge HTML (simplified)
	challengeHTML := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Security Challenge</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f5f5f5; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .container { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; max-width: 500px; }
        h1 { color: #333; margin-top: 0; }
        p { color: #666; line-height: 1.6; }
        .warning { background: #fff3cd; border: 1px solid #ffc107; border-radius: 4px; padding: 15px; margin: 20px 0; color: #856404; }
        .challenge-box { background: #f8f9fa; border: 2px solid #dee2e6; border-radius: 4px; padding: 20px; margin: 20px 0; }
        button { background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-size: 16px; }
        button:hover { background: #0056b3; }
        .info { font-size: 12px; color: #999; margin-top: 15px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Security Challenge</h1>
        <p>We've detected suspicious activity on your request. Please verify you're human by completing the challenge below.</p>

        <div class="warning">
            <strong>Threat Detected:</strong> %s
        </div>

        <div class="challenge-box">
            <p>This is a security challenge. In a production environment, this would display an hCaptcha or reCAPTCHA widget.</p>
            <p>Challenge ID: <code>%s</code></p>
            <form method="POST" action="/api/waf/challenge/verify">
                <input type="hidden" name="challenge_id" value="%s">
                <input type="hidden" name="original_request" value="%s">
                <button type="submit">I'm not a robot - Verify</button>
            </form>
        </div>

        <div class="info">
            <p>If you believe this is an error, please contact support.</p>
            <p>Your IP: %s</p>
        </div>
    </div>
</body>
</html>`, threat.Type, challengeID, challengeID, r.RequestURI, r.RemoteAddr)

	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(challengeHTML))
}

// handleNoneAction only logs the threat but allows the request to pass
func (h *WAFHandler) handleNoneAction(w http.ResponseWriter, r *http.Request, threat *detector.Threat) {
	// In detect mode, we don't block - just log and let it pass
	// The request continues to the backend application
	// This is handled at the middleware level, so we don't need to do anything here
	// The logger.LogJSON() already logged the threat above
}


// sendEventToAPI sends the threat event to the API for real-time dashboard updates
func (h *WAFHandler) sendEventToAPI(event map[string]interface{}) {
	eventJSON, err := json.Marshal(event)
	if err != nil {
		fmt.Printf("[ERROR] Failed to marshal event: %v\n", err)
		return
	}

	// Send to API endpoint
	resp, err := h.httpClient.Post(
		h.apiEndpoint+"/api/waf/event",
		"application/json",
		bytes.NewBuffer(eventJSON),
	)

	if err != nil {
		fmt.Printf("[ERROR] Failed to send event to API: %v\n", err)
		return
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("[WARN] API returned status %d when sending event\n", resp.StatusCode)
		return
	}

	fmt.Printf("[INFO] Event sent to API successfully: %s\n", event["threat"])
}