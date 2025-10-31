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
			"ip":         r.RemoteAddr,
			"method":     r.Method,
			"path":       r.RequestURI,
			"query":      r.URL.RawQuery,
			"user_agent": r.Header.Get("User-Agent"),
			"threat":     threat.Type,
			"payload":    threat.Payload,
			"timestamp":  time.Now().Format(time.RFC3339),
			"blocked":    true, // WAF handler only runs when threat is detected and blocked
		}

		// Log locally
		h.logger.LogJSON(event)

		// Send to API endpoint asynchronously (non-blocking)
		go h.sendEventToAPI(event)

		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
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