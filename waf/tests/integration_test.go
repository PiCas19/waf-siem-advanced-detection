package tests

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWAFIntegration(t *testing.T) {
	waf := &WAF{ /* mock */ }
	req := httptest.NewRequest("GET", "/?q=<script>", nil)
	rr := httptest.NewRecorder()
	waf.ServeHTTP(rr, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}))
	if rr.Code != 403 {
		t.Errorf("Expected 403, got %d", rr.Code)
	}
}