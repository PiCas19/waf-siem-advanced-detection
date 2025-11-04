package websocket

import (
	"encoding/json"
	"fmt"
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
	Blocked     bool   `json:"blocked"`
	BlockedBy   string `json:"blocked_by"`
}

func init() {
	go handleBroadcast()
}

func handleBroadcast() {
	for msg := range broadcast {
		mu.RLock()
		numClients := len(clients)
		fmt.Printf("[WebSocket] Broadcasting to %d clients: %s\n", numClients, string(msg))

		dead := make([]*websocket.Conn, 0)
		for client := range clients {
			err := client.WriteMessage(websocket.TextMessage, msg)
			if err != nil {
				fmt.Printf("[WebSocket] Error sending to client: %v\n", err)
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
	fmt.Printf("[WebSocket] Broadcast called with event: threat=%s, blocked=%v\n", event.Threat, event.Blocked)

	select {
	case broadcast <- jsonData:
		fmt.Printf("[WebSocket] ✅ Message queued for broadcast\n")
	default:
		fmt.Printf("[WebSocket] ⚠️  Broadcast channel full (100), dropping message\n")
	}
}

func WSHub(c *gin.Context) {
	fmt.Printf("[WebSocket] Client attempting to connect from %s\n", c.Request.RemoteAddr)

	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		fmt.Printf("[WebSocket] ❌ Upgrade failed: %v\n", err)
		return
	}

	mu.Lock()
	clients[conn] = true
	numClients := len(clients)
	mu.Unlock()

	fmt.Printf("[WebSocket] ✅ Client connected! Total clients: %d\n", numClients)

	defer func() {
		mu.Lock()
		delete(clients, conn)
		numClients := len(clients)
		mu.Unlock()
		conn.Close()
		fmt.Printf("[WebSocket] Client disconnected. Remaining clients: %d\n", numClients)
	}()

	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			fmt.Printf("[WebSocket] Client error: %v\n", err)
			break
		}
	}
}