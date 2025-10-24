package detector

import (
	"io"
	"net/http"
	"strings"
)

// Threat represents a detected security threat
type Threat struct {
	Type        string
	Description string
	Severity    string
	ClientIP    string
	Payload     string
}

// Detector orchestrates all security detectors
type Detector struct {
	xss     *XSSDetector
	sqli    *SQLiDetector
	lfi     *LFIDetector
	rfi     *RFIDetector
	cmdInj  *CommandInjectionDetector
}

// NewDetector creates a new Detector instance
func NewDetector() *Detector {
	return &Detector{
		xss:    NewXSSDetector(),
		sqli:   NewSQLiDetector(),
		lfi:    NewLFIDetector(),
		rfi:    NewRFIDetector(),
		cmdInj: NewCommandInjectionDetector(),
	}
}

// Inspect examines an HTTP request for security threats
func (d *Detector) Inspect(r *http.Request) *Threat {
	// Check URL query parameters
	for param, values := range r.URL.Query() {
		for _, value := range values {
			if threat := d.checkValue(r, param, value); threat != nil {
				return threat
			}
		}
	}
	
	// Check POST form data
	if r.Method == "POST" || r.Method == "PUT" {
		// Read and restore body
		body, err := io.ReadAll(r.Body)
		if err == nil {
			r.Body = io.NopCloser(strings.NewReader(string(body)))
			
			// Parse form
			r.ParseForm()
			for param, values := range r.PostForm {
				for _, value := range values {
					if threat := d.checkValue(r, param, value); threat != nil {
						return threat
					}
				}
			}
			
			// Also check raw body
			if threat := d.checkValue(r, "body", string(body)); threat != nil {
				return threat
			}
		}
	}
	
	// Check headers (excluding User-Agent which contains legitimate tool names)
	dangerousHeaders := []string{"Referer", "Cookie"}
	for _, header := range dangerousHeaders {
		if value := r.Header.Get(header); value != "" {
			if threat := d.checkValue(r, header, value); threat != nil {
				return threat
			}
		}
	}
	
	return nil
}

// checkValue runs all detectors on a single value
func (d *Detector) checkValue(r *http.Request, param, value string) *Threat {
	// XSS Detection
	if detected, desc := d.xss.Detect(value); detected {
		return &Threat{
			Type:        "XSS",
			Description: desc,
			Severity:    "HIGH",
			Payload:     value,
		}
	}
	
	// SQL Injection Detection
	if detected, desc := d.sqli.Detect(value); detected {
		return &Threat{
			Type:        "SQL_INJECTION",
			Description: desc,
			Severity:    "CRITICAL",
			Payload:     value,
		}
	}
	
	// LFI Detection
	if detected, desc := d.lfi.Detect(value); detected {
		return &Threat{
			Type:        "LFI",
			Description: desc,
			Severity:    "HIGH",
			Payload:     value,
		}
	}
	
	// RFI Detection
	if detected, desc := d.rfi.Detect(value); detected {
		return &Threat{
			Type:        "RFI",
			Description: desc,
			Severity:    "CRITICAL",
			Payload:     value,
		}
	}
	
	// Command Injection Detection
	if detected, desc := d.cmdInj.Detect(value); detected {
		return &Threat{
			Type:        "COMMAND_INJECTION",
			Description: desc,
			Severity:    "CRITICAL",
			Payload:     value,
		}
	}
	
	return nil
}