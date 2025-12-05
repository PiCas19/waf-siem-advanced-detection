// cmd/coraza-forwarder/main.go
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

type CorazaAuditLog struct {
	Transaction struct {
		ClientIP  string `json:"client_ip"`
		Timestamp string `json:"timestamp"`
		Request   struct {
			Method  string              `json:"method"`
			URI     string              `json:"uri"`
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

var (
	wafLogger *logger.Logger // globale così lo possiamo chiudere con defer
)

func main() {
	config := Config{}

	flag.StringVar(&config.CorazaLogFile, "coraza-log", "/var/log/caddy/coraza_audit.log", "Coraza audit log file")
	flag.StringVar(&config.WafLogFile, "waf-log", "/var/log/caddy/waf_wan.log", "WAF log file to write to")
	flag.StringVar(&config.APIEndpoint, "api", "http://localhost:8081/api", "API endpoint for dashboard")
	flag.DurationVar(&config.PollInterval, "poll", 1*time.Second, "Poll interval")
	flag.Parse()

	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.Printf("[INFO] Coraza Log Forwarder starting")
	log.Printf("[INFO] Coraza log → %s", config.CorazaLogFile)
	log.Printf("[INFO] WAF log    → %s", config.WafLogFile)
	log.Printf("[INFO] API        → %s/waf/event", config.APIEndpoint)

	// === INIZIALIZZAZIONE LOGGER WAF (CRITICA) ===
	var err error
	wafLogger, err = logger.NewLogger(config.WafLogFile)
	if err != nil {
		// NON morire, ma avvisa forte e disabilita scrittura su file
		log.Printf("[CRITICAL] Impossibile aprire %s in scrittura: %v", config.WafLogFile, err)
		log.Printf("[CRITICAL] Gli eventi Coraza verranno inviati all'API ma NON salvati in waf_wan.log")
		wafLogger = nil
	} else {
		log.Printf("[INFO] Logger WAF inizializzato correttamente: %s", config.WafLogFile)
		defer wafLogger.Close() // importantissimo!
	}

	// === APERTURA FILE CORAZA AUDIT LOG ===
	file, err := os.Open(config.CorazaLogFile)
	if err != nil {
		log.Fatalf("[FATAL] Impossibile aprire il log Coraza %s: %v", config.CorazaLogFile, err)
	}
	defer file.Close()

	// Vai in fondo al file per leggere solo le nuove righe
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		log.Fatalf("[FATAL] Seek fallito: %v", err)
	}

	// Segnali per shutdown pulito
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	reader := bufio.NewReader(file)
	ticker := time.NewTicker(config.PollInterval)
	defer ticker.Stop()

	log.Printf("[INFO] Monitoring Coraza audit log attivo... premi Ctrl+C per fermare")

	for {
		select {
		case <-sigChan:
			log.Printf("[INFO] Segnale di terminazione ricevuto, esco...")
			return

		case <-ticker.C:
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					if err == io.EOF {
						break // niente di nuovo
					}
					log.Printf("[ERROR] Errore lettura log: %v", err)
					break
				}

				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}

				processCorazaLog(line, config.APIEndpoint)
			}
		}
	}
}

func processCorazaLog(line string, apiEndpoint string) {
	var corazaLog CorazaAuditLog
	if err := json.Unmarshal([]byte(line), &corazaLog); err != nil {
		// Non è JSON valido → ignora (può essere header o riga di debug)
		return
	}

	// Ignora richieste non bloccate (solo 4xx/5xx)
	if corazaLog.Transaction.Response.HTTPCode < 400 {
		return
	}

	// Estrai dati minaccia
	threatType := "unknown"
	threatMsg := "OWASP CRS violation"
	payload := ""

	if len(corazaLog.Transaction.Messages) > 0 {
		m := corazaLog.Transaction.Messages[0]
		if m.Data.Msg != "" {
			threatMsg = m.Data.Msg
		}
		if m.Message != "" {
			payload = m.Message
		}

		file := strings.ToUpper(m.Data.File)
		switch {
		case strings.Contains(file, "XSS"):
			threatType = "xss"
		case strings.Contains(file, "SQLI"):
			threatType = "sqli"
		case strings.Contains(file, "RCE"), strings.Contains(file, "COMMAND"):
			threatType = "command_injection"
		case strings.Contains(file, "LFI"), strings.Contains(file, "TRAVERSAL"):
			threatType = "path_traversal"
		case strings.Contains(file, "RFI"):
			threatType = "rfi"
		case strings.Contains(file, "SCANNER"), strings.Contains(file, "BOT"):
			threatType = "scanner"
		case strings.Contains(file, "PROTOCOL"):
			threatType = "protocol_violation"
		}
	}

	// User-Agent
	userAgent := ""
	if ua, ok := corazaLog.Transaction.Request.Headers["User-Agent"]; ok && len(ua) > 0 {
		userAgent = ua[0]
	}

	// Timestamp
	ts, _ := time.Parse(time.RFC3339, corazaLog.Transaction.Timestamp)
	if ts.IsZero() {
		ts = time.Now()
	}

	// === SCRITTURA SU waf_wan.log (solo se logger valido) ===
	if wafLogger != nil {
		entry := logger.LogEntry{
			Timestamp:        ts,
			ThreatType:      threatType,
			Severity:       "high",
			Description:      threatMsg,
			ClientIP:        corazaLog.Transaction.ClientIP,
			ClientIPSource:  "remote-addr",
			ClientIPTrusted: false,
			Method:          corazaLog.Transaction.Request.Method,
			URL:             corazaLog.Transaction.Request.URI,
			UserAgent:       userAgent,
			Payload:         payload,
			Blocked:         true,
			BlockedBy:       "coraza",
		}

		if err := wafLogger.Log(entry); err != nil {
			log.Printf("[ERROR] Scrittura waf_wan.log fallita: %v", err)
		} else {
			log.Printf("[INFO] Coraza → waf_wan.log | %s | %s | %s", 
				corazaLog.Transaction.ClientIP, threatType, corazaLog.Transaction.Request.URI)
		}
	}

	// === INVIO ALL'API (sempre, anche se logger fallisce) ===
	sendToAPI(corazaLog, apiEndpoint)
}

func sendToAPI(corazaLog CorazaAuditLog, apiEndpoint string) {
	payload := map[string]interface{}{
		"ip":                   corazaLog.Transaction.ClientIP,
		"ip_source":            "direct",
		"ip_trusted":           false,
		"ip_source_type":       "direct",
		"ip_classification":     "untrusted",
		"threat":               "coraza_crs", // o estrai tipo come sopra se vuoi
		"description":          "OWASP CRS rule triggered",
		"method":              corazaLog.Transaction.Request.Method,
		"path":               corazaLog.Transaction.Request.URI,
		"user_agent":          "", // puoi estrarlo come sopra se vuoi
		"payload":             "", // idem
		"timestamp":           corazaLog.Transaction.Timestamp,
		"blocked":             true,
		"blocked_by":          "coraza",
		"ip_header_signature_valid": false,
		"ip_is_dmz":                 false,
		"ip_is_tailscale":           false,
		"ip_trust_score":            0,
	}

	jsonData, _ := json.Marshal(payload)

	resp, err := http.Post(apiEndpoint+"/waf/event", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("[ERROR] Invio API fallito: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		log.Printf("[WARN] API ha risposto con status %d", resp.StatusCode)
	} else {
		log.Printf("[INFO] Evento Coraza inviato al dashboard | IP: %s | Code: %d",
			corazaLog.Transaction.ClientIP, corazaLog.Transaction.Response.HTTPCode)
	}
}