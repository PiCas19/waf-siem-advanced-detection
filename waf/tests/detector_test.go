package tests

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/PiCas19/waf-siem-advanced-detection/waf/internal/detector"
)

func TestXSSDetection(t *testing.T) {
	d := detector.NewDetector()
	req := &http.Request{
		URL: &url.URL{RawQuery: "q=<script>alert(1)</script>"},
	}
	threat := d.Inspect(req)
	if threat == nil || threat.Type != "XSS" {
		t.Errorf("XSS not detected")
	}
}