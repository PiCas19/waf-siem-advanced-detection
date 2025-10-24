package websocket

import (
	"encoding/json"
	"sync"

	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

var (
	clients   = make(map[*websocket.Conn]bool)
	mu        sync.RWMutex
	broadcast = make(chan []byte, 100)
	upgrader  = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
)

type WAFEvent struct {
	IP        string `json:"ip"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Query     string `json:"query"`
	UA        string `json:"user_agent"`
	Timestamp string `json:"timestamp"`
	Threat    string `json:"threat"`
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