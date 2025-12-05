// cmd/coraza-forwarder/main.go
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
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
	WafWanLogFile string
	WafLanLogFile string
	APIEndpoint   string
	PollInterval  time.Duration
}

var (
	wafWanLogger *logger.Logger // Logger per traffico WAN
	wafLanLogger *logger.Logger // Logger per traffico LAN

	// Reti LAN/interne (basate su Caddyfile)
	lanNetworks = []string{
		"192.168.0.0/16",     // RFC 1918 private
		"172.16.0.0/12",      // RFC 1918 private
		"10.0.0.0/8",         // RFC 1918 private
		"100.64.0.0/10",      // Tailscale/CGNAT
		"127.0.0.0/8",        // Loopback
		"::1/128",            // IPv6 loopback
		"fe80::/10",          // IPv6 link-local
		"fc00::/7",           // IPv6 unique local
	}
	lanCIDRs []*net.IPNet
)

func main() {
	config := Config{}

	flag.StringVar(&config.CorazaLogFile, "coraza-log", "/var/log/caddy/coraza_audit.log", "Coraza audit log file")
	flag.StringVar(&config.WafWanLogFile, "waf-wan-log", "/var/log/caddy/waf_wan.log", "WAF WAN log file")
	flag.StringVar(&config.WafLanLogFile, "waf-lan-log", "/var/log/caddy/waf_lan.log", "WAF LAN log file")
	flag.StringVar(&config.APIEndpoint, "api", "http://localhost:8081/api", "API endpoint for dashboard")
	flag.DurationVar(&config.PollInterval, "poll", 1*time.Second, "Poll interval")
	flag.Parse()

	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.Printf("[INFO] Coraza Log Forwarder starting - Auto LAN/WAN detection")
	log.Printf("[INFO] Coraza log     → %s", config.CorazaLogFile)
	log.Printf("[INFO] WAF WAN log    → %s", config.WafWanLogFile)
	log.Printf("[INFO] WAF LAN log    → %s", config.WafLanLogFile)
	log.Printf("[INFO] API            → %s/waf/event", config.APIEndpoint)

	// === INIZIALIZZAZIONE RETI LAN ===
	initLANNetworks()

	// === INIZIALIZZAZIONE LOGGER WAF WAN ===
	var err error
	wafWanLogger, err = logger.NewLogger(config.WafWanLogFile)
	if err != nil {
		log.Printf("[CRITICAL] Impossibile aprire %s: %v", config.WafWanLogFile, err)
		log.Printf("[CRITICAL] Eventi WAN non verranno salvati su file")
		wafWanLogger = nil
	} else {
		log.Printf("[INFO] Logger WAF WAN inizializzato: %s", config.WafWanLogFile)
		defer wafWanLogger.Close()
	}

	// === INIZIALIZZAZIONE LOGGER WAF LAN ===
	wafLanLogger, err = logger.NewLogger(config.WafLanLogFile)
	if err != nil {
		log.Printf("[CRITICAL] Impossibile aprire %s: %v", config.WafLanLogFile, err)
		log.Printf("[CRITICAL] Eventi LAN non verranno salvati su file")
		wafLanLogger = nil
	} else {
		log.Printf("[INFO] Logger WAF LAN inizializzato: %s", config.WafLanLogFile)
		defer wafLanLogger.Close()
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

	// === DETERMINA SE LAN O WAN ===
	isLAN := isLANIP(corazaLog.Transaction.ClientIP)
	logType := "WAN"
	targetLogger := wafWanLogger
	if isLAN {
		logType = "LAN"
		targetLogger = wafLanLogger
	}

	// === SCRITTURA SU waf_wan.log O waf_lan.log ===
	if targetLogger != nil {
		entry := logger.LogEntry{
			Timestamp:        ts,
			ThreatType:      threatType,
			Severity:       "high",
			Description:      threatMsg,
			ClientIP:        corazaLog.Transaction.ClientIP,
			ClientIPSource:  "remote-addr",
			ClientIPTrusted: isLAN,
			Method:          corazaLog.Transaction.Request.Method,
			URL:             corazaLog.Transaction.Request.URI,
			UserAgent:       userAgent,
			Payload:         payload,
			Blocked:         true,
			BlockedBy:       "coraza",
		}

		if err := targetLogger.Log(entry); err != nil {
			log.Printf("[ERROR] Scrittura waf_%s.log fallita: %v", strings.ToLower(logType), err)
		} else {
			log.Printf("[INFO] Coraza → waf_%s.log | %s | %s | %s",
				strings.ToLower(logType), corazaLog.Transaction.ClientIP, threatType, corazaLog.Transaction.Request.URI)
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

// initLANNetworks inizializza le reti LAN in formato CIDR
func initLANNetworks() {
	lanCIDRs = make([]*net.IPNet, 0, len(lanNetworks))
	for _, cidr := range lanNetworks {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("[WARN] Errore parsing CIDR %s: %v", cidr, err)
			continue
		}
		lanCIDRs = append(lanCIDRs, network)
	}
	log.Printf("[INFO] %d reti LAN caricate per auto-detection", len(lanCIDRs))
}

// isLANIP verifica se un IP appartiene a una rete LAN/interna
func isLANIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false // IP non valido → considera WAN per sicurezza
	}

	// Controlla se appartiene a una delle reti LAN
	for _, network := range lanCIDRs {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}