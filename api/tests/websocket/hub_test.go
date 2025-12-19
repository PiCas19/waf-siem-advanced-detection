package websocket

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/PiCas19/waf-siem-advanced-detection/api/internal/websocket"
	"github.com/gin-gonic/gin"
	gorilla "github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// TestBroadcast_SingleClient tests broadcasting to a single connected client
func TestBroadcast_SingleClient(t *testing.T) {
	// Create test server
	router := gin.New()
	router.GET("/ws", websocket.WSHub)

	server := httptest.NewServer(router)
	defer server.Close()

	// Connect WebSocket client
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"
	conn, _, err := gorilla.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()

	// Give time for connection to establish
	time.Sleep(50 * time.Millisecond)

	// Create and broadcast WAF event
	event := websocket.WAFEvent{
		IP:          "192.168.1.100",
		Method:      "POST",
		Path:        "/admin/login",
		Query:       "username=admin",
		UA:          "Mozilla/5.0",
		Timestamp:   "2024-01-01T12:00:00Z",
		Threat:      "SQL Injection",
		Description: "SQL injection attempt detected",
		Payload:     "' OR 1=1--",
		Blocked:     true,
		BlockedBy:   "Custom WAF",
	}

	websocket.Broadcast(event)

	// Read broadcasted message
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	_, message, err := conn.ReadMessage()
	require.NoError(t, err)

	// Verify message structure
	var result map[string]interface{}
	err = json.Unmarshal(message, &result)
	require.NoError(t, err)

	assert.Equal(t, "waf_event", result["type"])
	data := result["data"].(map[string]interface{})
	assert.Equal(t, "192.168.1.100", data["ip"])
	assert.Equal(t, "POST", data["method"])
	assert.Equal(t, "SQL Injection", data["threat"])
	assert.Equal(t, true, data["blocked"])
}

// TestBroadcast_MultipleClients tests broadcasting to multiple connected clients
func TestBroadcast_MultipleClients(t *testing.T) {
	router := gin.New()
	router.GET("/ws", websocket.WSHub)

	server := httptest.NewServer(router)
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"

	// Connect multiple clients
	numClients := 3
	conns := make([]*gorilla.Conn, numClients)
	for i := 0; i < numClients; i++ {
		conn, _, err := gorilla.DefaultDialer.Dial(wsURL, nil)
		require.NoError(t, err)
		conns[i] = conn
		defer conn.Close()
	}

	// Give time for connections to establish
	time.Sleep(100 * time.Millisecond)

	// Broadcast event
	event := websocket.WAFEvent{
		IP:        "10.0.0.1",
		Method:    "GET",
		Path:      "/api/users",
		Threat:    "XSS",
		Blocked:   true,
		BlockedBy: "Coraza",
	}

	websocket.Broadcast(event)

	// Verify all clients received the message
	for i, conn := range conns {
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		_, message, err := conn.ReadMessage()
		require.NoError(t, err, "Client %d should receive message", i)

		var result map[string]interface{}
		err = json.Unmarshal(message, &result)
		require.NoError(t, err)

		assert.Equal(t, "waf_event", result["type"])
		data := result["data"].(map[string]interface{})
		assert.Equal(t, "10.0.0.1", data["ip"])
		assert.Equal(t, "XSS", data["threat"])
	}
}

// TestBroadcast_WithIPMetadata tests broadcasting with IP metadata fields
func TestBroadcast_WithIPMetadata(t *testing.T) {
	router := gin.New()
	router.GET("/ws", websocket.WSHub)

	server := httptest.NewServer(router)
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"
	conn, _, err := gorilla.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()

	time.Sleep(50 * time.Millisecond)

	// Event with IP metadata
	trustScore := 85
	reputation := 15
	event := websocket.WAFEvent{
		IP:            "203.0.113.50",
		Method:        "GET",
		Path:          "/",
		Threat:        "None",
		Blocked:       false,
		IPSource:      "x-forwarded-for",
		IPTrusted:     true,
		IPVPNReport:   false,
		IPTrustScore:  &trustScore,
		IPReputation:  &reputation,
		Country:       "US",
		ASN:           "AS15169",
	}

	websocket.Broadcast(event)

	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	_, message, err := conn.ReadMessage()
	require.NoError(t, err)

	var result map[string]interface{}
	err = json.Unmarshal(message, &result)
	require.NoError(t, err)

	data := result["data"].(map[string]interface{})
	assert.Equal(t, "x-forwarded-for", data["ip_source"])
	assert.Equal(t, true, data["ip_trusted"])
	assert.Equal(t, float64(85), data["ip_trust_score"])
	assert.Equal(t, float64(15), data["ip_reputation"])
	assert.Equal(t, "US", data["country"])
	assert.Equal(t, "AS15169", data["asn"])
}

// TestBroadcastEnrichment tests enrichment update broadcasting
func TestBroadcastEnrichment(t *testing.T) {
	router := gin.New()
	router.GET("/ws", websocket.WSHub)

	server := httptest.NewServer(router)
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"
	conn, _, err := gorilla.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()

	time.Sleep(50 * time.Millisecond)

	// Broadcast enrichment update
	ipReputation := 95
	abuseReports := 10
	websocket.BroadcastEnrichment(
		"198.51.100.42",
		&ipReputation,
		"critical",
		"CN",
		"AS4134",
		true,
		"AbuseIPDB",
		&abuseReports,
		true,
		"spamhaus",
	)

	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	_, message, err := conn.ReadMessage()
	require.NoError(t, err)

	var result map[string]interface{}
	err = json.Unmarshal(message, &result)
	require.NoError(t, err)

	assert.Equal(t, "enrichment_update", result["type"])
	data := result["data"].(map[string]interface{})
	assert.Equal(t, "198.51.100.42", data["ip"])
	assert.Equal(t, float64(95), data["ip_reputation"])
	assert.Equal(t, "critical", data["threat_level"])
	assert.Equal(t, "CN", data["country"])
	assert.Equal(t, "AS4134", data["asn"])
	assert.Equal(t, true, data["is_malicious"])
	assert.Equal(t, "AbuseIPDB", data["threat_source"])
	assert.Equal(t, float64(10), data["abuse_reports"])
	assert.Equal(t, true, data["is_on_blocklist"])
	assert.Equal(t, "spamhaus", data["blocklist_name"])
}

// TestBroadcastEnrichment_MultipleClients tests enrichment broadcasting to multiple clients
func TestBroadcastEnrichment_MultipleClients(t *testing.T) {
	router := gin.New()
	router.GET("/ws", websocket.WSHub)

	server := httptest.NewServer(router)
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"

	// Connect 2 clients
	conn1, _, err := gorilla.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn1.Close()

	conn2, _, err := gorilla.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn2.Close()

	time.Sleep(100 * time.Millisecond)

	// Broadcast enrichment
	ipRep := 50
	websocket.BroadcastEnrichment(
		"192.0.2.100",
		&ipRep,
		"medium",
		"RU",
		"AS12345",
		false,
		"VirusTotal",
		nil,
		false,
		"",
	)

	// Both clients should receive
	for i, conn := range []*gorilla.Conn{conn1, conn2} {
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		_, message, err := conn.ReadMessage()
		require.NoError(t, err, "Client %d should receive enrichment", i+1)

		var result map[string]interface{}
		err = json.Unmarshal(message, &result)
		require.NoError(t, err)

		assert.Equal(t, "enrichment_update", result["type"])
		data := result["data"].(map[string]interface{})
		assert.Equal(t, "192.0.2.100", data["ip"])
		assert.Equal(t, "medium", data["threat_level"])
	}
}

// TestWSHub_ConnectionAndDisconnection tests WebSocket connection lifecycle
func TestWSHub_ConnectionAndDisconnection(t *testing.T) {
	router := gin.New()
	router.GET("/ws", websocket.WSHub)

	server := httptest.NewServer(router)
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"

	// Connect
	conn, _, err := gorilla.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)

	time.Sleep(50 * time.Millisecond)

	// Send a broadcast to verify connection is active
	event := websocket.WAFEvent{
		IP:     "1.1.1.1",
		Threat: "Test",
	}
	websocket.Broadcast(event)

	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	_, _, err = conn.ReadMessage()
	assert.NoError(t, err, "Connected client should receive message")

	// Close connection
	conn.Close()

	// Give time for cleanup
	time.Sleep(100 * time.Millisecond)

	// Broadcast again - should not cause errors even though client disconnected
	websocket.Broadcast(event)

	// No assertion needed - just verifying no panic
}

// TestWSHub_MultipleConnections tests multiple simultaneous connections
func TestWSHub_MultipleConnections(t *testing.T) {
	router := gin.New()
	router.GET("/ws", websocket.WSHub)

	server := httptest.NewServer(router)
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"

	// Connect 5 clients
	conns := make([]*gorilla.Conn, 5)
	for i := 0; i < 5; i++ {
		conn, _, err := gorilla.DefaultDialer.Dial(wsURL, nil)
		require.NoError(t, err)
		conns[i] = conn
	}

	time.Sleep(100 * time.Millisecond)

	// Broadcast event
	event := websocket.WAFEvent{
		IP:     "172.16.0.1",
		Threat: "Port Scan",
	}
	websocket.Broadcast(event)

	// All clients should receive
	received := 0
	for _, conn := range conns {
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		_, _, err := conn.ReadMessage()
		if err == nil {
			received++
		}
	}

	assert.Equal(t, 5, received, "All 5 clients should receive the broadcast")

	// Close all connections
	for _, conn := range conns {
		conn.Close()
	}
}

// TestBroadcast_NoClients tests broadcasting with no connected clients
func TestBroadcast_NoClients(t *testing.T) {
	// Just broadcast without any clients - should not panic
	event := websocket.WAFEvent{
		IP:     "8.8.8.8",
		Threat: "None",
	}

	// Should not panic
	assert.NotPanics(t, func() {
		websocket.Broadcast(event)
	})
}

// TestBroadcastEnrichment_NoClients tests enrichment broadcasting with no clients
func TestBroadcastEnrichment_NoClients(t *testing.T) {
	ipRep := 10
	abuse := 5

	// Should not panic
	assert.NotPanics(t, func() {
		websocket.BroadcastEnrichment(
			"1.2.3.4",
			&ipRep,
			"low",
			"US",
			"AS1234",
			false,
			"Test",
			&abuse,
			false,
			"",
		)
	})
}

// TestBroadcast_RapidFireMessages tests multiple rapid broadcasts
func TestBroadcast_RapidFireMessages(t *testing.T) {
	router := gin.New()
	router.GET("/ws", websocket.WSHub)

	server := httptest.NewServer(router)
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"
	conn, _, err := gorilla.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()

	time.Sleep(50 * time.Millisecond)

	// Send multiple rapid broadcasts
	numMessages := 10
	for i := 0; i < numMessages; i++ {
		event := websocket.WAFEvent{
			IP:     "10.0.0.1",
			Threat: "Test",
		}
		websocket.Broadcast(event)
	}

	// Try to read messages
	received := 0
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for i := 0; i < numMessages; i++ {
		_, _, err := conn.ReadMessage()
		if err == nil {
			received++
		} else {
			break
		}
	}

	// Should receive most/all messages
	assert.GreaterOrEqual(t, received, numMessages-2, "Should receive most messages")
}

// TestBroadcast_JSONMarshaling tests that all event fields are properly marshaled
func TestBroadcast_JSONMarshaling(t *testing.T) {
	router := gin.New()
	router.GET("/ws", websocket.WSHub)

	server := httptest.NewServer(router)
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"
	conn, _, err := gorilla.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()

	time.Sleep(50 * time.Millisecond)

	// Event with all fields populated
	trustScore := 75
	reputation := 20
	event := websocket.WAFEvent{
		IP:            "203.0.113.100",
		Method:        "DELETE",
		Path:          "/api/data",
		Query:         "id=123&action=delete",
		UA:            "Custom Agent/1.0",
		Timestamp:     "2024-12-10T10:30:00Z",
		Threat:        "Command Injection",
		Description:   "Detected command injection pattern",
		Payload:       "; rm -rf /",
		Blocked:       true,
		BlockedBy:     "Custom WAF",
		IPSource:      "x-real-ip",
		IPTrusted:     false,
		IPVPNReport:   true,
		IPTrustScore:  &trustScore,
		IPReputation:  &reputation,
		Country:       "DE",
		ASN:           "AS3320",
	}

	websocket.Broadcast(event)

	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	_, message, err := conn.ReadMessage()
	require.NoError(t, err)

	// Verify JSON structure
	var result map[string]interface{}
	err = json.Unmarshal(message, &result)
	require.NoError(t, err)

	assert.Equal(t, "waf_event", result["type"])
	assert.NotNil(t, result["data"])

	// Unmarshal into WAFEvent to verify all fields
	dataJSON, _ := json.Marshal(result["data"])
	var receivedEvent websocket.WAFEvent
	err = json.Unmarshal(dataJSON, &receivedEvent)
	require.NoError(t, err)

	assert.Equal(t, event.IP, receivedEvent.IP)
	assert.Equal(t, event.Method, receivedEvent.Method)
	assert.Equal(t, event.Path, receivedEvent.Path)
	assert.Equal(t, event.Query, receivedEvent.Query)
	assert.Equal(t, event.UA, receivedEvent.UA)
	assert.Equal(t, event.Timestamp, receivedEvent.Timestamp)
	assert.Equal(t, event.Threat, receivedEvent.Threat)
	assert.Equal(t, event.Description, receivedEvent.Description)
	assert.Equal(t, event.Payload, receivedEvent.Payload)
	assert.Equal(t, event.Blocked, receivedEvent.Blocked)
	assert.Equal(t, event.BlockedBy, receivedEvent.BlockedBy)
	assert.Equal(t, event.IPSource, receivedEvent.IPSource)
	assert.Equal(t, event.IPTrusted, receivedEvent.IPTrusted)
	assert.Equal(t, event.IPVPNReport, receivedEvent.IPVPNReport)
	assert.Equal(t, *event.IPTrustScore, *receivedEvent.IPTrustScore)
	assert.Equal(t, *event.IPReputation, *receivedEvent.IPReputation)
	assert.Equal(t, event.Country, receivedEvent.Country)
	assert.Equal(t, event.ASN, receivedEvent.ASN)
}

// TestWSHub_InvalidUpgrade tests WebSocket upgrade failure handling
func TestWSHub_InvalidUpgrade(t *testing.T) {
	router := gin.New()
	router.GET("/ws", websocket.WSHub)

	// Make a regular HTTP request instead of WebSocket upgrade
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/ws", nil)
	// Don't set WebSocket upgrade headers

	router.ServeHTTP(w, req)

	// Should handle gracefully without panic
	// The upgrade will fail but the handler should return cleanly
	assert.NotEqual(t, http.StatusOK, w.Code)
}

// TestBroadcast_EmptyEvent tests broadcasting an empty event
func TestBroadcast_EmptyEvent(t *testing.T) {
	router := gin.New()
	router.GET("/ws", websocket.WSHub)

	server := httptest.NewServer(router)
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"
	conn, _, err := gorilla.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()

	time.Sleep(50 * time.Millisecond)

	// Empty event
	event := websocket.WAFEvent{}
	websocket.Broadcast(event)

	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	_, message, err := conn.ReadMessage()
	require.NoError(t, err)

	var result map[string]interface{}
	err = json.Unmarshal(message, &result)
	require.NoError(t, err)

	assert.Equal(t, "waf_event", result["type"])
	assert.NotNil(t, result["data"])
}

// TestBroadcastEnrichment_NilValues tests enrichment with nil pointer values
func TestBroadcastEnrichment_NilValues(t *testing.T) {
	router := gin.New()
	router.GET("/ws", websocket.WSHub)

	server := httptest.NewServer(router)
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"
	conn, _, err := gorilla.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()

	time.Sleep(50 * time.Millisecond)

	// Enrichment with nil values
	websocket.BroadcastEnrichment(
		"10.10.10.10",
		nil, // nil ip_reputation
		"low",
		"US",
		"",
		false,
		"",
		nil, // nil abuse_reports
		false,
		"",
	)

	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	_, message, err := conn.ReadMessage()
	require.NoError(t, err)

	var result map[string]interface{}
	err = json.Unmarshal(message, &result)
	require.NoError(t, err)

	assert.Equal(t, "enrichment_update", result["type"])
	data := result["data"].(map[string]interface{})
	assert.Equal(t, "10.10.10.10", data["ip"])
	assert.Nil(t, data["ip_reputation"])
	assert.Nil(t, data["abuse_reports"])
}

// TestBroadcast_ClientReconnect tests that a client can reconnect after disconnecting
func TestBroadcast_ClientReconnect(t *testing.T) {
	router := gin.New()
	router.GET("/ws", websocket.WSHub)

	server := httptest.NewServer(router)
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"

	// First connection
	conn1, _, err := gorilla.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)

	time.Sleep(50 * time.Millisecond)

	// Verify first connection works
	event := websocket.WAFEvent{IP: "1.1.1.1", Threat: "Test1"}
	websocket.Broadcast(event)

	conn1.SetReadDeadline(time.Now().Add(1 * time.Second))
	_, _, err = conn1.ReadMessage()
	assert.NoError(t, err)

	// Disconnect
	conn1.Close()
	time.Sleep(100 * time.Millisecond)

	// Reconnect
	conn2, _, err := gorilla.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn2.Close()

	time.Sleep(50 * time.Millisecond)

	// Verify second connection works
	event2 := websocket.WAFEvent{IP: "2.2.2.2", Threat: "Test2"}
	websocket.Broadcast(event2)

	conn2.SetReadDeadline(time.Now().Add(1 * time.Second))
	_, message, err := conn2.ReadMessage()
	require.NoError(t, err)

	var result map[string]interface{}
	json.Unmarshal(message, &result)
	data := result["data"].(map[string]interface{})
	assert.Equal(t, "2.2.2.2", data["ip"])
}
