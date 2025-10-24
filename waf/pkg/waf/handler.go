package waf

import (
	"net/http"

	"caddy-waf-project/waf/internal/detector"
	"caddy-waf-project/waf/internal/logger"
)

type WAFHandler struct {
	detector *detector.Detector
	logger   *logger.Logger
}

func NewWAFHandler(logPath string) (*WAFHandler, error) {
	l, err := logger.NewLogger(logPath)
	if err != nil {
		return nil, err
	}
	return &WAFHandler{
		detector: detector.NewDetector(),
		logger:   l,
	}, nil
}

func (h *WAFHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	threat := h.detector.Inspect(r)
	if threat != nil {
		event := map[string]interface{}{
			"ip":        r.RemoteAddr,
			"type":      threat.Type,
			"payload":   threat.Payload,
			"timestamp": time.Now().Format(time.RFC3339),
		}
		h.logger.LogJSON(event)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
}