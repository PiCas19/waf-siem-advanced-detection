package detector

import (
	"io"
	"net/http"
	"strings"

	"github.com/PiCas19/waf-siem-advanced-detection/waf/internal/ipextract"
)

type Threat struct {
	Type               string
	Description        string
	Severity           string
	ClientIP           string
	ClientIPSource     ipextract.ClientIPSource // Source of the IP extraction (x-public-ip, x-forwarded-for, x-real-ip, remote-addr)
	ClientIPTrusted    bool                     // Whether the IP source is trusted
	ClientIPVPNReport  bool                     // Whether this is a Tailscale/VPN self-reported IP
	Payload            string
	IsDefault          bool   // Indicates if this threat was detected by a default rule (always blocks)
	Action             string // "log" or "block" - action to take for custom rules
	BlockAction        string // "none", "block", "drop", "redirect", "challenge"
	RedirectURL        string // URL to redirect to (if BlockAction is "redirect")
	BlockEnabled       bool   // True if block action is selected
	DropEnabled        bool   // True if drop action is selected
	RedirectEnabled    bool   // True if redirect action is selected
	ChallengeEnabled   bool   // True if challenge action is selected
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
	customRules      *CustomRuleDetector
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
		customRules:    NewCustomRuleDetector(),
	}
}

// UpdateCustomRules updates the detector with custom rules from database
func (d *Detector) UpdateCustomRules(rules []*CustomRule) error {
	return d.customRules.UpdateRules(rules)
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
	// Extract client IP using robust multi-source extraction
	// Priority: X-Public-IP (Tailscale/VPN) > X-Forwarded-For (trusted proxy) > X-Real-IP (trusted proxy) > RemoteAddr
	ipInfo := ipextract.ExtractClientIPFromHeaders(
		r.Header.Get("X-Public-IP"),
		r.Header.Get("X-Forwarded-For"),
		r.Header.Get("X-Real-IP"),
		r.RemoteAddr,
	)

	// Helper function to create threat with IP info
	createThreat := func(threatType, desc, severity string) *Threat {
		return &Threat{
			Type:              threatType,
			Description:       desc,
			Severity:          severity,
			ClientIP:          ipInfo.IP,
			ClientIPSource:    ipInfo.Source,
			ClientIPTrusted:   ipInfo.IsTrusted,
			ClientIPVPNReport: ipInfo.IsVPNTailscale,
			Payload:           value,
			IsDefault:         true,
		}
	}

	// PRIORITY 1: Check MANUAL BLOCK rules first - they have highest priority
	// Manual block rules take precedence over everything else
	if manualBlockRule := d.customRules.DetectManualBlock(value); manualBlockRule != nil {
		blockAction := "none"
		if manualBlockRule.BlockEnabled {
			blockAction = "block"
		} else if manualBlockRule.DropEnabled {
			blockAction = "drop"
		} else if manualBlockRule.RedirectEnabled {
			blockAction = "redirect"
		} else if manualBlockRule.ChallengeEnabled {
			blockAction = "challenge"
		}

		return &Threat{
			Type:              manualBlockRule.Type,
			Description:       manualBlockRule.Name,
			Severity:          manualBlockRule.Severity,
			ClientIP:          ipInfo.IP,
			ClientIPSource:    ipInfo.Source,
			ClientIPTrusted:   ipInfo.IsTrusted,
			ClientIPVPNReport: ipInfo.IsVPNTailscale,
			Payload:           value,
			IsDefault:         false,
			Action:            manualBlockRule.Action,
			BlockAction:       blockAction,
			RedirectURL:       manualBlockRule.RedirectURL,
			BlockEnabled:      manualBlockRule.BlockEnabled,
			DropEnabled:       manualBlockRule.DropEnabled,
			RedirectEnabled:   manualBlockRule.RedirectEnabled,
			ChallengeEnabled:  manualBlockRule.ChallengeEnabled,
		}
	}

	// PRIORITY 2: Check default detectors
	if detected, desc := d.xss.Detect(value); detected {
		return createThreat("XSS", desc, "HIGH")
	}
	if detected, desc := d.sqli.Detect(value); detected {
		return createThreat("SQL_INJECTION", desc, "CRITICAL")
	}
	if detected, desc := d.nosql.Detect(value); detected {
		return createThreat("NOSQL_INJECTION", desc, "CRITICAL")
	}
	if detected, desc := d.lfi.Detect(value); detected {
		return createThreat("LFI", desc, "HIGH")
	}
	if detected, desc := d.pathTraversal.Detect(value); detected {
		return createThreat("PATH_TRAVERSAL", desc, "HIGH")
	}
	if detected, desc := d.rfi.Detect(value); detected {
		return createThreat("RFI", desc, "CRITICAL")
	}
	if detected, desc := d.ssrf.Detect(value); detected {
		return createThreat("SSRF", desc, "CRITICAL")
	}
	if detected, desc := d.cmdInj.Detect(value); detected {
		return createThreat("COMMAND_INJECTION", desc, "CRITICAL")
	}
	if detected, desc := d.xxe.Detect(value); detected {
		return createThreat("XXE", desc, "CRITICAL")
	}
	if detected, desc := d.ldap.Detect(value); detected {
		return createThreat("LDAP_INJECTION", desc, "HIGH")
	}
	if detected, desc := d.ssti.Detect(value); detected {
		return createThreat("SSTI", desc, "CRITICAL")
	}
	if detected, desc := d.respSplit.Detect(value); detected {
		return createThreat("HTTP_RESPONSE_SPLITTING", desc, "HIGH")
	}
	if detected, desc := d.protoPollution.Detect(value); detected {
		return createThreat("PROTOTYPE_POLLUTION", desc, "HIGH")
	}

	// PRIORITY 3: Check custom rules (non-manual-block rules)
	if customRule := d.customRules.Detect(value); customRule != nil {
		// Determine BlockAction based on which flag is enabled
		blockAction := "none"
		if customRule.BlockEnabled {
			blockAction = "block"
		} else if customRule.DropEnabled {
			blockAction = "drop"
		} else if customRule.RedirectEnabled {
			blockAction = "redirect"
		} else if customRule.ChallengeEnabled {
			blockAction = "challenge"
		}

		return &Threat{
			Type:              customRule.Type,
			Description:       customRule.Name,
			Severity:          customRule.Severity,
			ClientIP:          ipInfo.IP,
			ClientIPSource:    ipInfo.Source,
			ClientIPTrusted:   ipInfo.IsTrusted,
			ClientIPVPNReport: ipInfo.IsVPNTailscale,
			Payload:           value,
			IsDefault:         false, // Mark as custom rule
			Action:            customRule.Action, // "log" or "block"
			BlockAction:       blockAction,
			RedirectURL:       customRule.RedirectURL,
			BlockEnabled:      customRule.BlockEnabled,
			DropEnabled:       customRule.DropEnabled,
			RedirectEnabled:   customRule.RedirectEnabled,
			ChallengeEnabled:  customRule.ChallengeEnabled,
		}
	}

	return nil
}