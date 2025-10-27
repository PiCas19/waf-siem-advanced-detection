package detector

import (
	"io"
	"net/http"
	"strings"
)

type Threat struct {
	Type        string
	Description string
	Severity    string
	ClientIP    string
	Payload     string
	IsDefault   bool // Indicates if this threat was detected by a default rule (always blocks)
}

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
	for headerName, headerValues := range r.Header {
		for _, value := range headerValues {
			if threat := d.checkValue(r, headerName, value); threat != nil {
				return threat
			}
		}
	}

	for param, values := range r.URL.Query() {
		for _, value := range values {
			if threat := d.checkValue(r, param, value); threat != nil {
				return threat
			}
		}
	}

	if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
		body, err := io.ReadAll(r.Body)
		if err == nil {
			r.Body = io.NopCloser(strings.NewReader(string(body)))
			r.ParseForm()
			for param, values := range r.PostForm {
				for _, value := range values {
					if threat := d.checkValue(r, param, value); threat != nil {
						return threat
					}
				}
			}
			if threat := d.checkValue(r, "body", string(body)); threat != nil {
				return threat
			}
		}
	}

	return nil
}

func (d *Detector) checkValue(r *http.Request, param, value string) *Threat {
	if detected, desc := d.xss.Detect(value); detected {
		return &Threat{Type: "XSS", Description: desc, Severity: "HIGH", Payload: value, IsDefault: true}
	}
	if detected, desc := d.sqli.Detect(value); detected {
		return &Threat{Type: "SQL_INJECTION", Description: desc, Severity: "CRITICAL", Payload: value, IsDefault: true}
	}
	if detected, desc := d.nosql.Detect(value); detected {
		return &Threat{Type: "NOSQL_INJECTION", Description: desc, Severity: "CRITICAL", Payload: value, IsDefault: true}
	}
	if detected, desc := d.lfi.Detect(value); detected {
		return &Threat{Type: "LFI", Description: desc, Severity: "HIGH", Payload: value, IsDefault: true}
	}
	if detected, desc := d.pathTraversal.Detect(value); detected {
		return &Threat{Type: "PATH_TRAVERSAL", Description: desc, Severity: "HIGH", Payload: value, IsDefault: true}
	}
	if detected, desc := d.rfi.Detect(value); detected {
		return &Threat{Type: "RFI", Description: desc, Severity: "CRITICAL", Payload: value, IsDefault: true}
	}
	if detected, desc := d.ssrf.Detect(value); detected {
		return &Threat{Type: "SSRF", Description: desc, Severity: "CRITICAL", Payload: value, IsDefault: true}
	}
	if detected, desc := d.cmdInj.Detect(value); detected {
		return &Threat{Type: "COMMAND_INJECTION", Description: desc, Severity: "CRITICAL", Payload: value, IsDefault: true}
	}
	if detected, desc := d.xxe.Detect(value); detected {
		return &Threat{Type: "XXE", Description: desc, Severity: "CRITICAL", Payload: value, IsDefault: true}
	}
	if detected, desc := d.ldap.Detect(value); detected {
		return &Threat{Type: "LDAP_INJECTION", Description: desc, Severity: "HIGH", Payload: value, IsDefault: true}
	}
	if detected, desc := d.ssti.Detect(value); detected {
		return &Threat{Type: "SSTI", Description: desc, Severity: "CRITICAL", Payload: value, IsDefault: true}
	}
	if detected, desc := d.respSplit.Detect(value); detected {
		return &Threat{Type: "HTTP_RESPONSE_SPLITTING", Description: desc, Severity: "HIGH", Payload: value, IsDefault: true}
	}
	if detected, desc := d.protoPollution.Detect(value); detected {
		return &Threat{Type: "PROTOTYPE_POLLUTION", Description: desc, Severity: "HIGH", Payload: value, IsDefault: true}
	}
	return nil
}