package api

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/PiCas19/waf-siem-advanced-detection/waf/internal/logger"
)

// LogManualBlockRequest represents a manual block event to be logged to WAF logs
type LogManualBlockRequest struct {
	IP          string `json:"ip" binding:"required"`
	ThreatType  string `json:"threat_type" binding:"required"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// LogManualUnblockRequest represents a manual unblock event to be logged to WAF logs
type LogManualUnblockRequest struct {
	IP          string `json:"ip" binding:"required"`
	ThreatType  string `json:"threat_type" binding:"required"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// NewLogManualBlockHandler handles logging of manual block events to WAF logs
func NewLogManualBlockHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req LogManualBlockRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": "Invalid request"})
			return
		}

		// Write to WAF log files
		if err := writeToWAFLogsManualBlock(req); err != nil {
			log.Printf("[ERROR] Failed to write manual block to WAF logs: %v\n", err)
			c.JSON(500, gin.H{"error": "Failed to log event"})
			return
		}

		c.JSON(201, gin.H{"message": "Manual block logged successfully"})
	}
}

// NewLogManualUnblockHandler handles logging of manual unblock events to WAF logs
func NewLogManualUnblockHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req LogManualUnblockRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": "Invalid request"})
			return
		}

		// Write to WAF log files
		if err := writeToWAFLogsManualUnblock(req); err != nil {
			log.Printf("[ERROR] Failed to write manual unblock to WAF logs: %v\n", err)
			c.JSON(500, gin.H{"error": "Failed to log event"})
			return
		}

		c.JSON(201, gin.H{"message": "Manual unblock logged successfully"})
	}
}

// writeToWAFLogsManualBlock writes a manual block event to both WAF log files
func writeToWAFLogsManualBlock(req LogManualBlockRequest) error {
	logsDir := "/var/log/caddy"
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		return fmt.Errorf("failed to create logs directory: %v", err)
	}

	// Write to both WAN and LAN log files
	logFiles := []string{
		logsDir + "/waf_wan.log",
		logsDir + "/waf_lan.log",
	}

	for _, logFilePath := range logFiles {
		wafLogger, err := logger.NewLogger(logFilePath)
		if err != nil {
			log.Printf("[WARN] Failed to initialize WAF logger for %s: %v\n", logFilePath, err)
			continue
		}
		defer wafLogger.Close()

		entry := logger.LogEntry{
			Timestamp:       time.Now(),
			ThreatType:      req.ThreatType,
			Severity:        req.Severity,
			Description:     req.Description,
			ClientIP:        req.IP,
			ClientIPSource:  "manual-block",
			Method:          "MANUAL_BLOCK",
			Blocked:         true,
			BlockedBy:       "manual",
		}

		if err := wafLogger.Log(entry); err != nil {
			log.Printf("[WARN] Failed to log manual block to WAF file %s: %v\n", logFilePath, err)
		}
	}

	return nil
}

// writeToWAFLogsManualUnblock writes a manual unblock event to both WAF log files
func writeToWAFLogsManualUnblock(req LogManualUnblockRequest) error {
	logsDir := "/var/log/caddy"
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		return fmt.Errorf("failed to create logs directory: %v", err)
	}

	// Write to both WAN and LAN log files
	logFiles := []string{
		logsDir + "/waf_wan.log",
		logsDir + "/waf_lan.log",
	}

	for _, logFilePath := range logFiles {
		wafLogger, err := logger.NewLogger(logFilePath)
		if err != nil {
			log.Printf("[WARN] Failed to initialize WAF logger for %s: %v\n", logFilePath, err)
			continue
		}
		defer wafLogger.Close()

		entry := logger.LogEntry{
			Timestamp:      time.Now(),
			ThreatType:     req.ThreatType,
			Severity:       req.Severity,
			Description:    req.Description,
			ClientIP:       req.IP,
			ClientIPSource: "manual-unblock",
			Method:         "MANUAL_UNBLOCK",
			Blocked:        false,
			BlockedBy:      "",
		}

		if err := wafLogger.Log(entry); err != nil {
			log.Printf("[WARN] Failed to log manual unblock to WAF file %s: %v\n", logFilePath, err)
		}
	}

	return nil
}
