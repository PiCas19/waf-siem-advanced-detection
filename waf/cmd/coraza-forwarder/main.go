package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/waf/internal/logger"
)

// CorazaAuditLog represents Coraza audit log entry
type CorazaAuditLog struct {
	Transaction struct {
		ClientIP  string `json:"client_ip"`
		Timestamp string `json:"timestamp"`
		Request   struct {
			Method string `json:"method"`
			URI    string `json:"uri"`
			Headers map[string][]string `json:"headers"`
		} `json:"request"`
		Response struct {
			HTTPCode int `json:"http_code"`
		} `json:"response"`
		Messages []struct {
			Message string `json:"message"`
			Data    struct {
				Msg  string `json:"msg"`
				ID   string `json:"id"`
				File string `json:"file"`
			} `json:"data"`
		} `json:"messages"`
	} `json:"transaction"`
}

type Config struct {
	CorazaLogFile string
	WafLogFile    string
	APIEndpoint   string
	PollInterval  time.Duration
}

func main() {
	config := Config{}
	flag.StringVar(&config.CorazaLogFile, "coraza-log", "/var/log/caddy/coraza_audit.log", "Coraza audit log file")
	flag.StringVar(&config.WafLogFile, "waf-log", "/var/log/caddy/waf_wan.log", "WAF log file to write to")
	flag.StringVar(&config.APIEndpoint, "api", "http://localhost:8081/api", "API endpoint for dashboard")
	flag.DurationVar(&config.PollInterval, "poll", 1*time.Second, "Poll interval for log file")
	flag.Parse()

	log.Printf("[INFO] Coraza Log Forwarder starting...")
	log.Printf("[INFO]   Coraza log: %s", config.CorazaLogFile)
	log.Printf("[INFO]   WAF log:    %s", config.WafLogFile)
	log.Printf("[INFO]   API:        %s", config.APIEndpoint)

	// Create WAF logger
	wafLogger, err := logger.NewLogger(config.WafLogFile)
	if err != nil {
		log.Fatalf("[ERROR] Failed to create WAF logger: %v", err)
	}

	// Open Coraza log file
	file, err := os.Open(config.CorazaLogFile)
	if err != nil {
		log.Fatalf("[ERROR] Failed to open Coraza log: %v", err)
	}
	defer file.Close()

	// Seek to end of file to only process new entries
	_, err = file.Seek(0, io.SeekEnd)
	if err != nil {
		log.Fatalf("[ERROR] Failed to seek to end of file: %v", err)
	}

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	reader := bufio.NewReader(file)
	ticker := time.NewTicker(config.PollInterval)
	defer ticker.Stop()

	log.Printf("[INFO] Monitoring Coraza log file...")

	for {
		select {
		case <-sigChan:
			log.Printf("[INFO] Shutting down...")
			return

		case <-ticker.C:
			// Read new lines from file
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					if err == io.EOF {
						break
					}
					log.Printf("[ERROR] Error reading log: %v", err)
					break
				}

				// Process log line
				if strings.TrimSpace(line) != "" {
					processCorazaLog(line, wafLogger, config.APIEndpoint)
				}
			}
		}
	}
}

func processCorazaLog(line string, wafLogger *logger.Logger, apiEndpoint string) {
	var corazaLog CorazaAuditLog
	if err := json.Unmarshal([]byte(line), &corazaLog); err != nil {
		// Not JSON, might be plain text log - skip
		return
	}

	// Only process blocked requests (403, 4xx, 5xx)
	if corazaLog.Transaction.Response.HTTPCode < 400 {
		return
	}

	// Extract threat information from messages
	threatType := "unknown"
	threatMsg := "OWASP CRS violation"
	payload := ""

	if len(corazaLog.Transaction.Messages) > 0 {
		msg := corazaLog.Transaction.Messages[0]
		if msg.Data.Msg != "" {
			threatMsg = msg.Data.Msg
		}
		if msg.Message != "" {
			payload = msg.Message
		}

		// Determine threat type from rule file
		if strings.Contains(msg.Data.File, "XSS") {
			threatType = "xss"
		} else if strings.Contains(msg.Data.File, "SQLI") {
			threatType = "sqli"
		} else if strings.Contains(msg.Data.File, "RCE") {
			threatType = "command_injection"
		} else if strings.Contains(msg.Data.File, "LFI") {
			threatType = "path_traversal"
		} else if strings.Contains(msg.Data.File, "RFI") {
			threatType = "rfi"
		} else if strings.Contains(msg.Data.File, "SCANNER") {
			threatType = "scanner_detection"
		} else if strings.Contains(msg.Data.File, "PROTOCOL") {
			threatType = "protocol_violation"
		}
	}

	// Get User-Agent
	userAgent := ""
	if ua, ok := corazaLog.Transaction.Request.Headers["User-Agent"]; ok && len(ua) > 0 {
		userAgent = ua[0]
	}

	// Parse timestamp
	timestamp, _ := time.Parse(time.RFC3339, corazaLog.Transaction.Timestamp)
	if timestamp.IsZero() {
		timestamp = time.Now()
	}

	// Create LogEntry for WAF log
	logEntry := logger.LogEntry{
		Timestamp:       timestamp,
		ThreatType:      threatType,
		Severity:        "high",
		Description:     threatMsg,
		ClientIP:        corazaLog.Transaction.ClientIP,
		ClientIPSource:  "remote-addr", // Coraza uses direct IP
		ClientIPTrusted: false,
		Method:          corazaLog.Transaction.Request.Method,
		URL:             corazaLog.Transaction.Request.URI,
		UserAgent:       userAgent,
		Payload:         payload,
		Blocked:         true,
		BlockedBy:       "coraza", // Blocked by Coraza Layer 1
	}

	// Write to WAF log
	if err := wafLogger.Log(logEntry); err != nil {
		log.Printf("[ERROR] Failed to write to WAF log: %v", err)
	} else {
		log.Printf("[INFO] Logged Coraza block: IP=%s, Threat=%s, URL=%s",
			logEntry.ClientIP, logEntry.ThreatType, logEntry.URL)
	}

	// Send to dashboard API
	sendToAPI(logEntry, apiEndpoint)
}

func sendToAPI(logEntry logger.LogEntry, apiEndpoint string) {
	eventPayload := map[string]interface{}{
		"ip":               logEntry.ClientIP,
		"ip_source":        logEntry.ClientIPSource,
		"ip_trusted":       logEntry.ClientIPTrusted,
		"ip_vpn_reported":  logEntry.ClientIPVPNReport,
		"threat":           logEntry.ThreatType,
		"description":      logEntry.Description,
		"method":           logEntry.Method,
		"path":             logEntry.URL,
		"query":            "",
		"user_agent":       logEntry.UserAgent,
		"payload":          logEntry.Payload,
		"timestamp":        logEntry.Timestamp.Format(time.RFC3339),
		"blocked":          logEntry.Blocked,
		"blocked_by":       logEntry.BlockedBy,

		// IP detection defaults for Coraza (no advanced detection)
		"ip_source_type":           "direct",
		"ip_classification":        "untrusted",
		"ip_header_signature_valid": false,
		"ip_is_dmz":                 false,
		"ip_is_tailscale":           false,
		"ip_trust_score":            0,
		"ip_validation_details":     "",
	}

	jsonData, err := json.Marshal(eventPayload)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal event: %v", err)
		return
	}

	req, err := http.NewRequest("POST", apiEndpoint+"/waf/event", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("[ERROR] Failed to create API request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Failed to send event to API: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		log.Printf("[WARN] API returned status %d", resp.StatusCode)
	} else {
		log.Printf("[INFO] Event sent to dashboard: IP=%s, Threat=%s",
			logEntry.ClientIP, logEntry.ThreatType)
	}
}
