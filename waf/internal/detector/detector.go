package detector

import (
	"io"
	"net/http"
	"regexp"
	"strings"
)

// Threat represents a detected security threat
type Threat struct {
	Type        string
	Description string
	Severity    string
	ClientIP    string
	Payload     string
	Vector      string // Attack vector: "User-Agent", "Cookie", "Query Param", "POST Body", etc.
	Parameter   string // Specific parameter/header name
}

// Detector orchestrates all security detectors
type Detector struct {
	xss              *XSSDetector
	sqli             *SQLiDetector
	lfi              *LFIDetector
	rfi              *RFIDetector
	cmdInj           *CommandInjectionDetector
	xxe              *XXEDetector
	ssrf             *SSRFDetector
	nosql            *NoSQLInjectionDetector
	ldap             *LDAPInjectionDetector
	ssti             *SSTIDetector
	respSplit        *ResponseSplittingDetector
	protoPollution   *PrototypePollutionDetector
	pathTraversal    *PathTraversalDetector
}

// NewDetector creates a new Detector instance
func NewDetector() *Detector {
	return &Detector{
		xss:            NewXSSDetector(),
		sqli:           NewSQLiDetector(),
		lfi:            NewLFIDetector(),
		rfi:            NewRFIDetector(),
		cmdInj:         NewCommandInjectionDetector(),
		xxe:            NewXXEDetector(),
		ssrf:           NewSSRFDetector(),
		nosql:          NewNoSQLInjectionDetector(),
		ldap:           NewLDAPInjectionDetector(),
		ssti:           NewSSTIDetector(),
		respSplit:      NewResponseSplittingDetector(),
		protoPollution: NewPrototypePollutionDetector(),
		pathTraversal:  NewPathTraversalDetector(),
	}
}


func (d *Detector) Inspect(r *http.Request) *Threat {
	// 🔥 CHECK ALL HEADERS (attackers can use any header)
	for headerName, headerValues := range r.Header {
		for _, value := range headerValues {
			if threat := d.checkValue(r, headerName, value, "Header"); threat != nil {
				return threat
			}
		}
	}

	// 🍪 CHECK COOKIES INDIVIDUALLY
	for _, cookie := range r.Cookies() {
		if threat := d.checkValue(r, cookie.Name, cookie.Value, "Cookie"); threat != nil {
			return threat
		}
	}

	// 🔗 CHECK URL PATH AND FRAGMENT
	if r.URL.Path != "" {
		if threat := d.checkValue(r, "path", r.URL.Path, "URL Path"); threat != nil {
			return threat
		}
	}
	if r.URL.Fragment != "" {
		if threat := d.checkValue(r, "fragment", r.URL.Fragment, "URL Fragment"); threat != nil {
			return threat
		}
	}

	// ❓ CHECK URL QUERY PARAMETERS
	for param, values := range r.URL.Query() {
		for _, value := range values {
			if threat := d.checkValue(r, param, value, "Query Parameter"); threat != nil {
				return threat
			}
		}
	}

	// 📤 CHECK POST/PUT/PATCH BODY
	if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
		// Read and restore body
		body, err := io.ReadAll(r.Body)
		if err == nil {
			r.Body = io.NopCloser(strings.NewReader(string(body)))
			bodyStr := string(body)

			// Parse form data
			r.ParseForm()
			for param, values := range r.PostForm {
				for _, value := range values {
					if threat := d.checkValue(r, param, value, "POST Parameter"); threat != nil {
						return threat
					}
				}
			}

			// Check raw body (for JSON, XML, etc.)
			if threat := d.checkValue(r, "body", bodyStr, "Request Body"); threat != nil {
				return threat
			}

			// 📋 CHECK JSON BODY (if Content-Type is JSON)
			if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
				if threat := d.checkJSONBody(r, bodyStr); threat != nil {
					return threat
				}
			}
		}
	}

	return nil
}

// checkValue runs all detectors on a single value
func (d *Detector) checkValue(r *http.Request, param, value, vector string) *Threat {
	// XSS Detection
	if detected, desc := d.xss.Detect(value); detected {
		return &Threat{
			Type:        "XSS",
			Description: desc,
			Severity:    "HIGH",
			Payload:     value,
			Vector:      vector,
			Parameter:   param,
		}
	}

	// SQL Injection Detection
	if detected, desc := d.sqli.Detect(value); detected {
		return &Threat{
			Type:        "SQL_INJECTION",
			Description: desc,
			Severity:    "CRITICAL",
			Payload:     value,
			Vector:      vector,
			Parameter:   param,
		}
	}

	// NoSQL Injection Detection
	if detected, desc := d.nosql.Detect(value); detected {
		return &Threat{
			Type:        "NOSQL_INJECTION",
			Description: desc,
			Severity:    "CRITICAL",
			Payload:     value,
			Vector:      vector,
			Parameter:   param,
		}
	}

	// LFI Detection
	if detected, desc := d.lfi.Detect(value); detected {
		return &Threat{
			Type:        "LFI",
			Description: desc,
			Severity:    "HIGH",
			Payload:     value,
			Vector:      vector,
			Parameter:   param,
		}
	}

	// Path Traversal Detection
	if detected, desc := d.pathTraversal.Detect(value); detected {
		return &Threat{
			Type:        "PATH_TRAVERSAL",
			Description: desc,
			Severity:    "HIGH",
			Payload:     value,
			Vector:      vector,
			Parameter:   param,
		}
	}

	// RFI Detection
	if detected, desc := d.rfi.Detect(value); detected {
		return &Threat{
			Type:        "RFI",
			Description: desc,
			Severity:    "CRITICAL",
			Payload:     value,
			Vector:      vector,
			Parameter:   param,
		}
	}

	// SSRF Detection
	if detected, desc := d.ssrf.Detect(value); detected {
		return &Threat{
			Type:        "SSRF",
			Description: desc,
			Severity:    "CRITICAL",
			Payload:     value,
			Vector:      vector,
			Parameter:   param,
		}
	}

	// Command Injection Detection
	if detected, desc := d.cmdInj.Detect(value); detected {
		return &Threat{
			Type:        "COMMAND_INJECTION",
			Description: desc,
			Severity:    "CRITICAL",
			Payload:     value,
			Vector:      vector,
			Parameter:   param,
		}
	}

	// XXE Detection
	if detected, desc := d.xxe.Detect(value); detected {
		return &Threat{
			Type:        "XXE",
			Description: desc,
			Severity:    "CRITICAL",
			Payload:     value,
			Vector:      vector,
			Parameter:   param,
		}
	}

	// LDAP Injection Detection
	if detected, desc := d.ldap.Detect(value); detected {
		return &Threat{
			Type:        "LDAP_INJECTION",
			Description: desc,
			Severity:    "HIGH",
			Payload:     value,
			Vector:      vector,
			Parameter:   param,
		}
	}

	// SSTI Detection
	if detected, desc := d.ssti.Detect(value); detected {
		return &Threat{
			Type:        "SSTI",
			Description: desc,
			Severity:    "CRITICAL",
			Payload:     value,
			Vector:      vector,
			Parameter:   param,
		}
	}

	// HTTP Response Splitting Detection
	if detected, desc := d.respSplit.Detect(value); detected {
		return &Threat{
			Type:        "HTTP_RESPONSE_SPLITTING",
			Description: desc,
			Severity:    "HIGH",
			Payload:     value,
			Vector:      vector,
			Parameter:   param,
		}
	}

	// Prototype Pollution Detection
	if detected, desc := d.protoPollution.Detect(value); detected {
		return &Threat{
			Type:        "PROTOTYPE_POLLUTION",
			Description: desc,
			Severity:    "HIGH",
			Payload:     value,
			Vector:      vector,
			Parameter:   param,
		}
	}

	return nil
}

// checkJSONBody recursively checks JSON body for attacks
func (d *Detector) checkJSONBody(r *http.Request, jsonBody string) *Threat {
	// Simple approach: check if JSON contains suspicious patterns
	// For more advanced parsing, use encoding/json

	// Check common JSON injection patterns
	jsonPatterns := []string{
		`":\s*"<script`,
		`":\s*"javascript:`,
		`":\s*"\s*OR\s+1=1`,
		`":\s*".*\.\./`,
		`":\s*".*http://`,
		`":\s*".*https://`,
	}

	for _, pattern := range jsonPatterns {
		if matched, _ := regexp.MatchString(`(?i)`+pattern, jsonBody); matched {
			// Run full detection on the entire JSON
			return d.checkValue(r, "json_body", jsonBody, "JSON Body")
		}
	}

	return nil
}