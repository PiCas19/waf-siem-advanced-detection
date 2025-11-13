package websocket

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

var (
	clients   = make(map[*websocket.Conn]bool)
	mu        sync.RWMutex
	broadcast = make(chan []byte, 100)
	upgrader  = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			_ = r.Header.Get("Origin") 
			return true              
		},
	}
)

type WAFEvent struct {
	IP          string `json:"ip"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	Query       string `json:"query"`
	UA          string `json:"user_agent"`
	Timestamp   string `json:"timestamp"`
	Threat      string `json:"threat"`
	Description string `json:"description"` // Rule name/description for per-rule blocking
	Payload     string `json:"payload"`     // Detected malicious payload
	Blocked     bool   `json:"blocked"`
	BlockedBy   string `json:"blocked_by"`

	// IP Source Metadata (from WAF)
	IPSource   string `json:"ip_source,omitempty"`    // How IP was extracted: x-public-ip, x-forwarded-for, x-real-ip, remote-addr
	IPTrusted  bool   `json:"ip_trusted,omitempty"`   // Whether the IP source is from a trusted source
	IPVPNReport bool  `json:"ip_vpn_reported,omitempty"` // Whether this is a self-reported IP from Tailscale/VPN
}

func init() {
	go handleBroadcast()
}

func handleBroadcast() {
	for msg := range broadcast {
		mu.RLock()
		dead := make([]*websocket.Conn, 0)
		for client := range clients {
			err := client.WriteMessage(websocket.TextMessage, msg)
			if err != nil {
				dead = append(dead, client)
			}
		}
		mu.RUnlock()

		mu.Lock()
		for _, conn := range dead {
			delete(clients, conn)
			conn.Close()
		}
		mu.Unlock()
	}
}

func Broadcast(event WAFEvent) {
	data := map[string]any{
		"type": "waf_event",
		"data": event,
	}
	jsonData, _ := json.Marshal(data)

	select {
	case broadcast <- jsonData:
	default:
		// Broadcast channel full, dropping message
	}
}

func WSHub(c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}

	mu.Lock()
	clients[conn] = true
	mu.Unlock()

	defer func() {
		mu.Lock()
		delete(clients, conn)
		mu.Unlock()
		conn.Close()
	}()

	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}