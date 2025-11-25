package api

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/service"
)

// NewExportLogsHandler godoc
// @Summary Export security logs
// @Description Exports security logs in CSV, JSON, or XML format
// @Tags Export
// @Accept json
// @Produce text/csv,application/json,application/xml
// @Param format query string true "Export format (csv, json, xml)" default(json)
// @Param limit query int false "Maximum number of logs to export (default 1000, max 10000)" default(1000)
// @Success 200 {string} string "Exported logs"
// @Failure 400 {object} map[string]interface{} "Invalid format or parameters"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /export/logs [get]
// @Security BearerAuth
func NewExportLogsHandler(logService *service.LogService) gin.HandlerFunc {
	return func(c *gin.Context) {
		format := c.DefaultQuery("format", "json")
		limitStr := c.DefaultQuery("limit", "1000")

		// Validate format
		if format != "csv" && format != "json" && format != "xml" {
			BadRequestWithCode(c, ErrInvalidRequest, "Invalid format. Must be: csv, json, or xml")
			return
		}

		// Parse limit with validation
		var limit int
		_, err := fmt.Sscanf(limitStr, "%d", &limit)
		if err != nil || limit < 1 || limit > 10000 {
			BadRequestWithCode(c, ErrInvalidRequest, "Limit must be between 1 and 10000")
			return
		}

		ctx := c.Request.Context()
		logs, _, err := logService.GetLogsPaginated(ctx, 0, limit)
		if err != nil {
			InternalServerErrorWithCode(c, ErrServiceError, "Failed to fetch logs")
			return
		}

		// Set appropriate content type and filename
		timestamp := time.Now().Format("20060102_150405")
		filename := fmt.Sprintf("security_logs_%s", timestamp)

		switch format {
		case "csv":
			c.Header("Content-Type", "text/csv")
			c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.csv"`, filename))
			exportLogsAsCSV(c, logs)

		case "json":
			c.Header("Content-Type", "application/json")
			c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.json"`, filename))
			c.JSON(200, gin.H{
				"count": len(logs),
				"data":  logs,
			})

		case "xml":
			c.Header("Content-Type", "application/xml")
			c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.xml"`, filename))
			exportLogsAsXML(c, logs)
		}
	}
}

// NewExportAuditLogsHandler godoc
// @Summary Export audit logs
// @Description Exports audit logs in CSV or JSON format
// @Tags Export
// @Accept json
// @Produce text/csv,application/json
// @Param format query string true "Export format (csv, json)" default(json)
// @Param limit query int false "Maximum number of logs to export (default 1000, max 10000)" default(1000)
// @Success 200 {string} string "Exported audit logs"
// @Failure 400 {object} map[string]interface{} "Invalid format or parameters"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /export/audit-logs [get]
// @Security BearerAuth
func NewExportAuditLogsHandler(auditLogService *service.AuditLogService) gin.HandlerFunc {
	return func(c *gin.Context) {
		format := c.DefaultQuery("format", "json")
		limitStr := c.DefaultQuery("limit", "1000")

		// Validate format
		if format != "csv" && format != "json" && format != "xml" {
			BadRequestWithCode(c, ErrInvalidRequest, "Invalid format. Must be: csv, json, or xml")
			return
		}

		// Parse limit with validation
		var limit int
		_, err := fmt.Sscanf(limitStr, "%d", &limit)
		if err != nil || limit < 1 || limit > 10000 {
			BadRequestWithCode(c, ErrInvalidRequest, "Limit must be between 1 and 10000")
			return
		}

		ctx := c.Request.Context()
		auditLogs, _, err := auditLogService.GetPaginatedAuditLogs(ctx, 1, limit)
		if err != nil {
			InternalServerErrorWithCode(c, ErrServiceError, "Failed to fetch audit logs")
			return
		}

		// Set appropriate content type and filename
		timestamp := time.Now().Format("20060102_150405")
		filename := fmt.Sprintf("audit_logs_%s", timestamp)

		switch format {
		case "csv":
			c.Header("Content-Type", "text/csv")
			c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.csv"`, filename))
			exportAuditLogsAsCSV(c, auditLogs)

		case "json":
			c.Header("Content-Type", "application/json")
			c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.json"`, filename))
			c.JSON(200, gin.H{
				"count": len(auditLogs),
				"data":  auditLogs,
			})

		case "xml":
			c.Header("Content-Type", "application/xml")
			c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.xml"`, filename))
			exportAuditLogsAsXML(c, auditLogs)
		}
	}
}

// NewExportBlocklistHandler godoc
// @Summary Export blocklist
// @Description Exports blocked IPs in CSV or JSON format
// @Tags Export
// @Accept json
// @Produce text/csv,application/json
// @Param format query string true "Export format (csv, json)" default(json)
// @Success 200 {string} string "Exported blocklist"
// @Failure 400 {object} map[string]interface{} "Invalid format"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /export/blocklist [get]
// @Security BearerAuth
func NewExportBlocklistHandler(blocklistService *service.BlocklistService) gin.HandlerFunc {
	return func(c *gin.Context) {
		format := c.DefaultQuery("format", "json")

		// Validate format
		if format != "csv" && format != "json" && format != "xml" {
			BadRequestWithCode(c, ErrInvalidRequest, "Invalid format. Must be: csv, json, or xml")
			return
		}

		ctx := c.Request.Context()
		blockedIPs, err := blocklistService.GetActiveBlockedIPs(ctx)
		if err != nil {
			InternalServerErrorWithCode(c, ErrServiceError, "Failed to fetch blocked IPs")
			return
		}

		// Set appropriate content type and filename
		timestamp := time.Now().Format("20060102_150405")
		filename := fmt.Sprintf("blocklist_%s", timestamp)

		switch format {
		case "csv":
			c.Header("Content-Type", "text/csv")
			c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.csv"`, filename))
			exportBlocklistAsCSV(c, blockedIPs)

		case "json":
			c.Header("Content-Type", "application/json")
			c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.json"`, filename))
			c.JSON(200, gin.H{
				"count": len(blockedIPs),
				"data":  blockedIPs,
			})

		case "xml":
			c.Header("Content-Type", "application/xml")
			c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.xml"`, filename))
			exportBlocklistAsXML(c, blockedIPs)
		}
	}
}

// exportLogsAsCSV exports logs as CSV format
func exportLogsAsCSV(c *gin.Context, logs interface{}) {
	c.Header("Content-Type", "text/csv; charset=utf-8")

	writer := csv.NewWriter(c.Writer)
	defer writer.Flush()

	// Write headers
	headers := []string{"ID", "Created At", "Threat Type", "Severity", "Description", "Client IP", "Client IP Source", "Method", "URL", "User Agent", "Payload", "Blocked", "Blocked By"}
	if err := writer.Write(headers); err != nil {
		return
	}

	// Write data
	if logSlice, ok := logs.(interface{}); ok {
		logsJSON, _ := json.Marshal(logSlice)
		var logsData []map[string]interface{}
		json.Unmarshal(logsJSON, &logsData)

		for _, log := range logsData {
			record := []string{
				fmt.Sprintf("%v", log["id"]),
				fmt.Sprintf("%v", log["created_at"]),
				fmt.Sprintf("%v", log["threat_type"]),
				fmt.Sprintf("%v", log["severity"]),
				fmt.Sprintf("%v", log["description"]),
				fmt.Sprintf("%v", log["client_ip"]),
				fmt.Sprintf("%v", log["client_ip_source"]),
				fmt.Sprintf("%v", log["method"]),
				fmt.Sprintf("%v", log["url"]),
				fmt.Sprintf("%v", log["user_agent"]),
				fmt.Sprintf("%v", log["payload"]),
				fmt.Sprintf("%v", log["blocked"]),
				fmt.Sprintf("%v", log["blocked_by"]),
			}
			writer.Write(record)
		}
	}
}

// exportAuditLogsAsCSV exports audit logs as CSV format
func exportAuditLogsAsCSV(c *gin.Context, logs interface{}) {
	c.Header("Content-Type", "text/csv; charset=utf-8")

	writer := csv.NewWriter(c.Writer)
	defer writer.Flush()

	// Write headers
	headers := []string{"ID", "User ID", "User Email", "Action", "Resource Type", "Resource ID", "Details", "Status", "Created At", "Client IP"}
	if err := writer.Write(headers); err != nil {
		return
	}

	// Write data
	if logSlice, ok := logs.(interface{}); ok {
		logsJSON, _ := json.Marshal(logSlice)
		var logsData []map[string]interface{}
		json.Unmarshal(logsJSON, &logsData)

		for _, log := range logsData {
			record := []string{
				fmt.Sprintf("%v", log["id"]),
				fmt.Sprintf("%v", log["user_id"]),
				fmt.Sprintf("%v", log["user_email"]),
				fmt.Sprintf("%v", log["action"]),
				fmt.Sprintf("%v", log["resource_type"]),
				fmt.Sprintf("%v", log["resource_id"]),
				fmt.Sprintf("%v", log["details"]),
				fmt.Sprintf("%v", log["status"]),
				fmt.Sprintf("%v", log["created_at"]),
				fmt.Sprintf("%v", log["client_ip"]),
			}
			writer.Write(record)
		}
	}
}

// exportBlocklistAsCSV exports blocklist as CSV format
func exportBlocklistAsCSV(c *gin.Context, blockedIPs interface{}) {
	c.Header("Content-Type", "text/csv; charset=utf-8")

	writer := csv.NewWriter(c.Writer)
	defer writer.Flush()

	// Write headers
	headers := []string{"ID", "IP Address", "Description", "Reason", "Permanent", "Expires At", "Created At", "URL", "User Agent", "Payload"}
	if err := writer.Write(headers); err != nil {
		return
	}

	// Write data
	if ipSlice, ok := blockedIPs.(interface{}); ok {
		ipsJSON, _ := json.Marshal(ipSlice)
		var ipsData []map[string]interface{}
		json.Unmarshal(ipsJSON, &ipsData)

		for _, ip := range ipsData {
			record := []string{
				fmt.Sprintf("%v", ip["id"]),
				fmt.Sprintf("%v", ip["ip_address"]),
				fmt.Sprintf("%v", ip["description"]),
				fmt.Sprintf("%v", ip["reason"]),
				fmt.Sprintf("%v", ip["permanent"]),
				fmt.Sprintf("%v", ip["expires_at"]),
				fmt.Sprintf("%v", ip["created_at"]),
				fmt.Sprintf("%v", ip["url"]),
				fmt.Sprintf("%v", ip["user_agent"]),
				fmt.Sprintf("%v", ip["payload"]),
			}
			writer.Write(record)
		}
	}
}

// exportLogsAsXML exports logs as XML format (simple wrapper)
func exportLogsAsXML(c *gin.Context, logs interface{}) {
	c.Header("Content-Type", "application/xml; charset=utf-8")
	c.Writer.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	c.Writer.WriteString(`<logs>`)

	logsJSON, _ := json.Marshal(logs)
	var logsData []map[string]interface{}
	json.Unmarshal(logsJSON, &logsData)

	for _, log := range logsData {
		logBytes, _ := json.Marshal(log)
		logXML := convertJSONToXML("log", logBytes)
		c.Writer.WriteString(logXML)
	}

	c.Writer.WriteString(`</logs>`)
}

// exportAuditLogsAsXML exports audit logs as XML format
func exportAuditLogsAsXML(c *gin.Context, logs interface{}) {
	c.Header("Content-Type", "application/xml; charset=utf-8")
	c.Writer.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	c.Writer.WriteString(`<audit_logs>`)

	logsJSON, _ := json.Marshal(logs)
	var logsData []map[string]interface{}
	json.Unmarshal(logsJSON, &logsData)

	for _, log := range logsData {
		logBytes, _ := json.Marshal(log)
		logXML := convertJSONToXML("audit_log", logBytes)
		c.Writer.WriteString(logXML)
	}

	c.Writer.WriteString(`</audit_logs>`)
}

// exportBlocklistAsXML exports blocklist as XML format
func exportBlocklistAsXML(c *gin.Context, blockedIPs interface{}) {
	c.Header("Content-Type", "application/xml; charset=utf-8")
	c.Writer.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	c.Writer.WriteString(`<blocked_ips>`)

	ipsJSON, _ := json.Marshal(blockedIPs)
	var ipsData []map[string]interface{}
	json.Unmarshal(ipsJSON, &ipsData)

	for _, ip := range ipsData {
		ipBytes, _ := json.Marshal(ip)
		ipXML := convertJSONToXML("blocked_ip", ipBytes)
		c.Writer.WriteString(ipXML)
	}

	c.Writer.WriteString(`</blocked_ips>`)
}

// convertJSONToXML converts JSON to simple XML format
func convertJSONToXML(elementName string, jsonData []byte) string {
	var data map[string]interface{}
	json.Unmarshal(jsonData, &data)

	xml := fmt.Sprintf(`<%s>`, elementName)
	for key, val := range data {
		xml += fmt.Sprintf(`<%s>%v</%s>`, key, val, key)
	}
	xml += fmt.Sprintf(`</%s>`, elementName)

	return xml
}
