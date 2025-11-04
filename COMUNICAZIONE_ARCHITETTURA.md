# Architettura e Comunicazione WAF-Backend: Spiegazione Completa

## Indice
1. [Overview Architettura](#overview-architettura)
2. [Meccanismi di Comunicazione](#meccanismi-di-comunicazione)
3. [Flusso dei Dati](#flusso-dei-dati)
4. [Dettagli Tecnici](#dettagli-tecnici)
5. [Diagrammi](#diagrammi)

---

## Overview Architettura

Il progetto è diviso in **3 componenti principali** che comunicano tra loro:

```
┌──────────┐         ┌────────────┐         ┌───────────┐
│ Caddy    │         │  Backend   │         │ Dashboard │
│   WAF    │◄───────►│   API      │◄───────►│  React    │
└──────────┘         └────────────┘         └───────────┘
  Port 8080           Ports 8081-83       Browser HTTP(s)
  Port 8443
```

---

## Meccanismi di Comunicazione

### 1. **REST API - HTTP POST (Sincrono)**
**Scopo**: WAF invia eventi al backend

- **Direzione**: WAF → API
- **Endpoint**: `POST /api/waf/event`
- **Quando**: Ogni volta che il WAF rileva una minaccia
- **Protocollo**: HTTP 1.1
- **Formato Dati**: JSON
- **Timeout**: 5 secondi

**Payload Esempio**:
```json
{
  "ip": "192.168.1.100",
  "method": "GET",
  "path": "/api/users",
  "query": "?id=1 OR 1=1",
  "user_agent": "Mozilla/5.0...",
  "threat": "SQL Injection",
  "blocked": true,
  "blocked_by": "auto",
  "timestamp": "2025-11-04T14:30:45Z"
}
```

**Flusso**:
1. Cliente fa HTTP request al WAF
2. WAF middleware analizza la request
3. Se minaccia rilevata → POST a `/api/waf/event` (non-blocking)
4. API riceve → Salva in DB → Broadcast via WebSocket
5. Dashboard riceve via WebSocket → Aggiorna UI

---

### 2. **WebSocket (Real-time)**
**Scopo**: Comunicazione real-time API → Dashboard

- **Direzione**: API → Dashboard
- **Endpoint**: `ws://host/ws` o `wss://host/ws`
- **Protocollo**: WebSocket (RFC 6455)
- **Latenza**: Milliseconds
- **Connessioni Simultanee**: ~100 per server

**Funzionamento**:
1. Dashboard stabilisce connessione WebSocket al server
2. Server mantiene la connessione aperta
3. Quando WAF invia evento a `/api/waf/event`, il server lo riceve
4. Server fa **broadcast** a TUTTI i WebSocket client connessi
5. Dashboard riceve il messaggio in tempo reale

**Struttura Messaggio WebSocket**:
```json
{
  "type": "waf_event",
  "data": {
    "id": 123,
    "ip": "192.168.1.100",
    "method": "GET",
    "path": "/api/users",
    "threat": "SQL Injection",
    "blocked": true,
    "timestamp": "2025-11-04T14:30:45Z"
  }
}
```

**Vantaggi**:
- ✅ Real-time (no delay)
- ✅ Basso overhead (connessione persistente)
- ✅ Bidirezione (non usato in questo caso)

---

### 3. **HTTP Polling (Fallback)**
**Scopo**: Fallback se WebSocket non disponibile

- **Direzione**: Dashboard → API
- **Endpoint**: `GET /api/stats`
- **Frequenza**: Ogni 10 secondi
- **Formato Dati**: JSON

**Quando si usa**:
- Se WebSocket non supportato dal browser
- Se proxy/firewall blocca WebSocket
- Fallback automatico nel frontend

**Response Esempio**:
```json
{
  "stats": {
    "threats_detected": 150,
    "requests_blocked": 45,
    "total_requests": 5000
  },
  "recent_threats": [
    {
      "ip": "10.0.0.5",
      "threat": "XSS",
      "timestamp": "2025-11-04T14:30:45Z"
    }
  ]
}
```

**Limitazioni**:
- ❌ Non real-time (ritardo fino a 10 secondi)
- ❌ Consuma più bandwidth
- ❌ Load sul server aumentato

---

### 4. **REST API - GET Periodico (Rule Loading)**
**Scopo**: WAF carica regole custom dal backend

- **Direzione**: WAF → API
- **Endpoint**: `GET /api/waf/custom-rules`
- **Frequenza**:
  - Al startup (immediato)
  - Ogni 60 secondi (background reload)
- **Protocollo**: HTTP 1.1

**Quando si usa**:
- Quando WAF avvia
- Periodicamente per aggiornamenti regole
- Non bloccante (il WAF continua a funzionare se l'API è down)

**Response Esempio**:
```json
{
  "rules": [
    {
      "id": 1,
      "name": "Custom SQL Injection",
      "pattern": "(?i)(union|select|insert|delete)\\s+",
      "type": "CUSTOM_PATTERN",
      "severity": "HIGH",
      "action": "log",
      "enabled": true
    },
    {
      "id": 2,
      "name": "Rilevamento traversal path",
      "pattern": "\\.\\.[\\\\/]",
      "type": "PATH_TRAVERSAL",
      "severity": "MEDIUM",
      "action": "block",
      "enabled": true
    }
  ],
  "count": 2
}
```

---

### 5. **REST API - Dashboard Admin Operations**
**Scopo**: Amministratore gestisce regole e blocklist

- **Direzione**: Dashboard → API
- **Endpoint**:
  - `GET /api/rules` - Legge regole
  - `POST /api/rules` - Crea nuova regola
  - `PUT /api/rules/:id` - Modifica regola
  - `DELETE /api/rules/:id` - Cancella regola
  - `POST /api/blocklist` - Aggiunge IP a blocklist
  - `DELETE /api/blocklist/:ip` - Rimuove IP da blocklist
- **Quando**: On-demand (quando admin interagisce)

**Flusso Creazione Regola**:
1. Admin compila form nel Dashboard
2. Clicca "Create Rule"
3. Dashboard → POST `/api/rules` con dati regola
4. API salva nel DB
5. A questo punto:
   - Prossimi WAF che ricaricano le regole (ogni 60s) riceveranno la nuova regola
   - O immediatamente se l'admin forza il reload

---

## Flusso dei Dati

### Flusso 1: Rilevamento e Notifica Evento

```
┌──────────────────────────────────────────────────────────────────────┐
│                    FLUSSO EVENTO WAF COMPLETO                         │
└──────────────────────────────────────────────────────────────────────┘

STEP 1: CLIENT INVIA REQUEST
────────────────────────────────
┌─────────────────────────────────────────────────────────────────────┐
│ Client → HTTP Request → Caddy (Port 8080/8443)                       │
│ Esempio: GET /api/users?id=1' OR '1'='1                             │
└─────────────────────────────────────────────────────────────────────┘

STEP 2: WAF ANALIZA REQUEST
────────────────────────────────
┌─────────────────────────────────────────────────────────────────────┐
│ waf/pkg/waf/middleware.go → ServeHTTP()                              │
│ ├─ Detector.Inspect(request)                                        │
│ │  ├─ Controlla DEFAULT RULES (XSS, SQLi, LFI, RFI, etc.)           │
│ │  └─ Controlla CUSTOM RULES (da API, ogni 60s)                    │
│ └─ Risultato: Minaccia rilevata!                                    │
│    - threat: "SQL Injection"                                        │
│    - blocked: true (se in block mode)                               │
└─────────────────────────────────────────────────────────────────────┘

STEP 3: WAF INVIA EVENTO ALL'API (ASINCRONO)
──────────────────────────────────────────────
┌─────────────────────────────────────────────────────────────────────┐
│ WAF → POST http://localhost:8081/api/waf/event                      │
│ ├─ Headers: Content-Type: application/json                          │
│ ├─ Body: JSON con ip, method, path, query, threat, timestamp, ecc. │
│ └─ Timeout: 5 secondi                                               │
│    (Se l'API è down, il WAF continua comunque)                      │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
STEP 4: API RICEVE EVENTO
──────────────────────────
┌─────────────────────────────────────────────────────────────────────┐
│ api/internal/api/stats.go → NewWAFEventHandler()                     │
│ ├─ Parse JSON → websocket.WAFEvent struct                           │
│ ├─ Salva nel DB (INSERT INTO logs)                                  │
│ │  └─ Campi: threat_type, client_ip, method, url, blocked, etc.    │
│ ├─ Aggiorna Stats in memoria:                                       │
│ │  ├─ stats.ThreatsDetected++                                       │
│ │  ├─ stats.RequestsBlocked++ (se blocked=true)                    │
│ │  ├─ stats.TotalRequests++                                         │
│ │  └─ stats.Recent = append(ultime 5 minacce)                      │
│ └─ Response: HTTP 200 OK                                            │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
STEP 5: API BROADCAST VIA WEBSOCKET
─────────────────────────────────────
┌─────────────────────────────────────────────────────────────────────┐
│ api/internal/websocket/hub.go → Broadcast(event)                    │
│ ├─ Converte evento in WebSocket message                             │
│ │  └─ { "type": "waf_event", "data": {...} }                       │
│ ├─ Invia a TUTTI i client WebSocket connessi                        │
│ │  ├─ Client 1 (Admin Dashboard)     → Riceve via WebSocket         │
│ │  ├─ Client 2 (Security Monitor)    → Riceve via WebSocket         │
│ │  ├─ Client 3 (Offline)             → Nessuna ricezione            │
│ │  └─ Buffering: max 100 messaggi in coda                           │
│ └─ Se client disconnect → rimosso automaticamente                   │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
STEP 6: DASHBOARD RICEVE VIA WEBSOCKET
───────────────────────────────────────
┌─────────────────────────────────────────────────────────────────────┐
│ dashboard/src/services/websocket.ts → onmessage()                   │
│ ├─ Parse JSON message                                               │
│ ├─ Se type === "waf_event":                                         │
│ │  ├─ Aggiorna React state (stats, recentThreats, ecc.)            │
│ │  ├─ Chiama callback listeners:                                   │
│ │  │  ├─ LogViewer.tsx → Mostra nuovo evento in tabella             │
│ │  │  ├─ StatsPage.tsx → Aggiorna contatori                        │
│ │  │  ├─ AlertPanel.tsx → Notifica pop-up                           │
│ │  │  └─ RecentThreats.tsx → Aggiorna lista                         │
│ │  └─ setState() trigger re-render                                  │
│ └─ Immediatamente visibile all'utente (~10-50ms)                    │
└─────────────────────────────────────────────────────────────────────┘
                              ↓
STEP 7: UTENTE VEDE L'EVENTO IN REAL-TIME
──────────────────────────────────────────
┌─────────────────────────────────────────────────────────────────────┐
│ Dashboard mostra:                                                   │
│ ┌─────────────────────────────────────────────────────────────────┐ │
│ │ ALERT: SQL Injection                                           │ │
│ │ IP: 192.168.1.100                                              │ │
│ │ Method: GET                                                     │ │
│ │ Path: /api/users                                               │ │
│ │ Query: ?id=1' OR '1'='1                                         │ │
│ │ Status: BLOCKED                                                 │ │
│ │ Time: 14:30:45                                                  │ │
│ └─────────────────────────────────────────────────────────────────┘ │
│                                                                    │
│ Counters Updated:                                                 │
│ ├─ Threats Detected: 150 → 151                                   │
│ ├─ Requests Blocked: 45 → 46                                     │
│ └─ Total Requests: 5000 → 5001                                   │
└─────────────────────────────────────────────────────────────────────┘

LATENZA TOTALE: ~50-200ms (Real-time!)
```

---

### Flusso 2: Caricamento Regole Custom

```
┌──────────────────────────────────────────────────────────────────────┐
│                  FLUSSO CARICAMENTO REGOLE CUSTOM                    │
└──────────────────────────────────────────────────────────────────────┘

STARTUP WAF
───────────
Caddy avvia →
  waf/pkg/waf/middleware.go → Provision()
    ├─ Inizializza detector, logger, httpClient
    │
    └─ Se RulesEndpoint configurato nel Caddyfile:
       │
       └─ loadCustomRulesFromAPI() IMMEDIATAMENTE
          │
          ├─ GET http://localhost:8081/api/waf/custom-rules
          │  │ (senza autenticazione)
          │  │
          │  └─ API Response:
          │     {
          │       "rules": [
          │         { id, name, pattern, type, severity, action, enabled },
          │         ...
          │       ],
          │       "count": N
          │     }
          │
          ├─ Compila regex patterns da patterns string
          │
          └─ detector.UpdateCustomRules(rules)
             └─ Salva in memoria nel CustomRuleDetector


RELOAD PERIODICO OGNI 60 SECONDI
─────────────────────────────────
WAF start → reloadRulesBackground() goroutine
             │
             ├─ ticker := time.NewTicker(60 * time.Second)
             │
             └─ Loop infinito:
                ├─ Attende 60 secondi
                │
                ├─ Esegui loadCustomRulesFromAPI() (stesso di startup)
                │  └─ GET /api/waf/custom-rules
                │     └─ Aggiorna CustomRuleDetector in memoria
                │
                └─ Se errore: Log warning, continua comunque
                   (WAF non dipende da API per funzionare)


SCENARIO: ADMIN CREA NUOVA REGOLA
──────────────────────────────────
Admin Dashboard:
  ├─ Compila form (name, pattern, type, action)
  ├─ Clicca "Create Rule"
  └─ POST /api/rules con dati
       │
       └─ API salva nel DB
            │
            └─ Regola disponibile in GET /api/waf/custom-rules
                 │
                 └─ WAF la carica al prossimo reload (entro 60s)
```

---

## Dettagli Tecnici

### Configurazione WAF (Caddyfile)

```
:8080 :8443 {
    waf {
        # Log file per registrare gli eventi
        log_file /var/log/caddy/waf_wan.log

        # Modalità blocco globale
        block_mode true

        # Endpoint dove il WAF INVIA gli eventi rilevati
        api_endpoint http://localhost:8081/api/waf/event

        # Endpoint dove il WAF LEGGE le regole custom
        rules_endpoint http://localhost:8081/api/waf/custom-rules
    }

    # Reverse proxy per API
    reverse_proxy /api/* http://localhost:8081 http://localhost:8082 http://localhost:8083

    # Reverse proxy per WebSocket
    reverse_proxy /ws http://localhost:8081 http://localhost:8082 http://localhost:8083
}
```

---

### Strutture Dati Principali

**WAF Event (da WAF a API)**:
```go
type WAFEvent struct {
    IP         string    `json:"ip"`
    Method     string    `json:"method"`
    Path       string    `json:"path"`
    Query      string    `json:"query"`
    UserAgent  string    `json:"user_agent"`
    Threat     string    `json:"threat"`
    Blocked    bool      `json:"blocked"`
    BlockedBy  string    `json:"blocked_by"` // "auto" o "admin"
    Timestamp  time.Time `json:"timestamp"`
}
```

**Custom Rule (da API a WAF)**:
```go
type Rule struct {
    ID          uint      `json:"id"`
    Name        string    `json:"name"`
    Pattern     string    `json:"pattern"`       // Regex
    Type        string    `json:"type"`
    Severity    string    `json:"severity"`
    Action      string    `json:"action"`         // "log" o "block"
    Enabled     bool      `json:"enabled"`
    BlockEnabled bool     `json:"block_enabled"`
    // ... altri campi
}
```

---

### Performance e Limitazioni

| Aspetto | Valore | Note |
|---------|--------|------|
| **WebSocket Clients Max** | ~100 per server | Dipende da RAM/CPU |
| **WebSocket Message Buffer** | 100 messaggi | Dopo si disconnette il client |
| **Rule Reload Frequency** | 60 secondi | Configurabile |
| **API Event Timeout** | 5 secondi | Non-blocking |
| **Stats Polling** | 10 secondi | Fallback |
| **Average Event Latency** | 50-200ms | Da evento a UI |
| **Throughput HTTP Events** | ~1000 event/s | Dipende da HW |

---

### Sicurezza

#### WebSocket
- ✅ Connessione persistente = secure per streaming
- ⚠️ CheckOrigin: true (accetta qualsiasi origine)
  - **In Produzione**: Implementare CORS proper

#### API Endpoints
- ✅ `/api/waf/event` - Pubblico (WAF invia)
- ✅ `/api/waf/custom-rules` - Pubblico (WAF legge)
- ⚠️ `/api/rules`, `/api/blocklist` - Dovrebbe avere autenticazione
- ✅ `/ws` - Connessione diretta (niente autenticazione per vederlo?)

---

## Diagrammi

### Architettura Generale

```
                    INTERNET
                       │
                       ▼
        ┌──────────────────────────────┐
        │   CADDY + WAF Middleware     │
        │   (Port 8080 HTTP)            │
        │   (Port 8443 HTTPS)           │
        │                              │
        │  ├─ Inspect Requests          │
        │  ├─ Check Rules               │
        │  ├─ Block/Allow               │
        │  └─ POST /api/waf/event      │ Event invocation
        └──────────────────────────────┘
           │                     │
           │ /api/*              │ /ws
           ▼                     ▼
        ┌──────────────────────────────────────┐
        │   Backend API Server (Gin)            │
        │   Ports: 8081, 8082, 8083             │
        │                                      │
        │  ├─ POST /api/waf/event             │
        │  │  ├─ Parse Event                  │
        │  │  ├─ Save to DB                   │
        │  │  └─ Broadcast via WebSocket ─────┼─ Real-time
        │  │                                  │
        │  ├─ GET /api/waf/custom-rules      │
        │  │  └─ Return enabled rules         │
        │  │                                  │
        │  ├─ GET /api/stats                 │
        │  │  └─ Return statistics            │
        │  │                                  │
        │  └─ CRUD /api/rules                │
        │     └─ Manage custom rules          │
        │                                    │
        │   Database (SQLite/PostgreSQL)     │
        │   ├─ logs (events)                  │
        │   ├─ rules (custom)                 │
        │   ├─ blocked_ips                    │
        │   └─ audit_logs                     │
        └──────────────────────────────────────┘
                       ▲
                       │ ws:// (WebSocket)
                       │
        ┌──────────────────────────────┐
        │  Dashboard (React.js)          │
        │  Browser Tab                  │
        │                              │
        │  ├─ Real-time Events (WS)    │
        │  ├─ Stats Polling (HTTP)     │
        │  ├─ Rules Management         │
        │  └─ IP Blocking              │
        └──────────────────────────────┘
```

### Timeline Evento

```
Time →

0ms     100ms           150ms           200ms           250ms
│       │               │               │               │
│       │               │               │               │
Client  WAF            API             WebSocket      Dashboard
  │      Detects        Receives        Broadcasts     Updates
  │      Attack         → Saves DB      → All clients  → User sees
  │      │              → Stats         → Alert        │
  └─POST→ event         updated         panel shows    │
         /api/waf/event                 in real-time   │
                                                       │
                            Total Latency: ~200ms
```

---

## Riassunto

### Le 3 Tecnologie Principali di Comunicazione:

1. **REST API (HTTP POST)** - WAF → API
   - Quando: Ogni evento
   - Latenza: ~50-100ms
   - Carattere: Sincrono ma asincrono nell'implementazione

2. **WebSocket** - API → Dashboard
   - Quando: Ogni broadcast
   - Latenza: Real-time (~10-50ms)
   - Carattere: Push (server invia ai client)

3. **Polling (HTTP GET)** - Dashboard → API (fallback)
   - Quando: Se WebSocket non funziona
   - Frequenza: Ogni 10 secondi
   - Latenza: Max 10 secondi

### Quando Usare Cosa:

- **REST API Sincrono**: Per operazioni CRUD (Create, Read, Update, Delete) di regole e blocklist
- **WebSocket**: Per notifiche real-time di eventi
- **Polling**: Come fallback se WebSocket non disponibile
- **REST API GET Periodico**: Per WAF di ricaricare regole non bloccante

### Vantaggi dell'Architettura:

✅ **Real-time**: WebSocket per notifiche istantanee
✅ **Resiliente**: WAF continua se API è down
✅ **Scalabile**: Polling periodico non blocca
✅ **Modular**: Componenti indipendenti
✅ **Secure**: Separazione componenti + HTTPS
