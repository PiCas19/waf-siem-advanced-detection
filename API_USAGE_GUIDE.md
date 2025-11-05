# Guida Completa agli Endpoint API

## Autenticazione

Tutti gli endpoint (tranne `/auth/login`) richiedono un token JWT nel header:
```
Authorization: Bearer YOUR_JWT_TOKEN
```

Per ottenere il token:
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@example.com",
    "password": "your_password"
  }'
```

Risposta:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "email": "admin@example.com",
    "name": "Admin",
    "role": "admin"
  }
}
```

---

## 1. WHITELIST - Gestire IP Affidabili

### 1.1 Recuperare la lista di IP whitelisted
**Metodo:** GET
**URL:** `/api/whitelist`
**Header:** `Authorization: Bearer {token}`

```bash
curl -X GET http://localhost:8080/api/whitelist \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Risposta di successo (200):
```json
{
  "count": 2,
  "whitelisted_ips": [
    {
      "id": 1,
      "ip_address": "192.168.1.100",
      "reason": "Office network",
      "added_by": 1,
      "created_at": "2024-11-05T10:30:00Z",
      "updated_at": "2024-11-05T10:30:00Z"
    },
    {
      "id": 2,
      "ip_address": "10.0.0.1",
      "reason": "Partner API",
      "added_by": 1,
      "created_at": "2024-11-05T11:15:00Z",
      "updated_at": "2024-11-05T11:15:00Z"
    }
  ]
}
```

---

### 1.2 Aggiungere un IP alla whitelist
**Metodo:** POST
**URL:** `/api/whitelist`
**Header:** `Authorization: Bearer {token}`
**Body:** JSON

```bash
curl -X POST http://localhost:8080/api/whitelist \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ip_address": "203.0.113.45",
    "reason": "Trusted partner for API integrations"
  }'
```

Parametri:
- `ip_address` (required): IP address da whitelistare (es: "192.168.1.1" oppure IPv6)
- `reason` (optional): Motivo della whitelist

Risposta di successo (201):
```json
{
  "message": "IP whitelisted successfully",
  "ip": {
    "id": 3,
    "ip_address": "203.0.113.45",
    "reason": "Trusted partner for API integrations",
    "added_by": 1,
    "created_at": "2024-11-05T12:00:00Z",
    "updated_at": "2024-11-05T12:00:00Z"
  }
}
```

Errori possibili:
- `400` - IP non valido oppure formato JSON non valido
- `409` - IP già presente nella whitelist

---

### 1.3 Rimuovere un IP dalla whitelist
**Metodo:** DELETE
**URL:** `/api/whitelist/:id`
**Header:** `Authorization: Bearer {token}`

```bash
curl -X DELETE http://localhost:8080/api/whitelist/3 \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Parametri URL:
- `id` (required): ID dell'entry da rimuovere (es: 3)

Risposta di successo (200):
```json
{
  "message": "IP removed from whitelist successfully"
}
```

Errori possibili:
- `404` - IP non trovato
- `500` - Errore del server

---

## 2. FALSE POSITIVES - Gestire Falsi Positivi

### 2.1 Recuperare la lista di False Positives
**Metodo:** GET
**URL:** `/api/false-positives`
**Header:** `Authorization: Bearer {token}`

```bash
curl -X GET http://localhost:8080/api/false-positives \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Risposta di successo (200):
```json
{
  "count": 2,
  "false_positives": [
    {
      "id": 1,
      "threat_type": "XSS",
      "client_ip": "192.168.1.50",
      "method": "GET",
      "url": "/api/search?q=<script>alert(1)</script>",
      "payload": "<script>alert(1)</script>",
      "user_agent": "Mozilla/5.0...",
      "status": "pending",
      "review_notes": null,
      "reviewed_by": null,
      "reviewed_at": null,
      "created_at": "2024-11-05T10:30:00Z",
      "updated_at": "2024-11-05T10:30:00Z"
    },
    {
      "id": 2,
      "threat_type": "SQL_INJECTION",
      "client_ip": "10.0.0.50",
      "method": "POST",
      "url": "/api/users",
      "payload": "name=test'; DROP TABLE users;--",
      "user_agent": "curl/7.64.1",
      "status": "reviewed",
      "review_notes": "Legitimate developer testing",
      "reviewed_by": 1,
      "reviewed_at": "2024-11-05T11:45:00Z",
      "created_at": "2024-11-05T11:00:00Z",
      "updated_at": "2024-11-05T11:45:00Z"
    }
  ]
}
```

---

### 2.2 Segnalare un nuovo False Positive
**Metodo:** POST
**URL:** `/api/false-positives`
**Header:** `Authorization: Bearer {token}`
**Body:** JSON

```bash
curl -X POST http://localhost:8080/api/false-positives \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "threat_type": "XSS",
    "client_ip": "192.168.1.100",
    "method": "POST",
    "url": "/api/comments",
    "payload": "comment=<b>This is bold text</b>",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
  }'
```

Parametri:
- `threat_type` (required): Tipo di minaccia rilevata (es: "XSS", "SQL_INJECTION", "API_ENUMERATION")
- `client_ip` (required): IP del client che ha fatto la richiesta
- `method` (optional): Metodo HTTP (GET, POST, PUT, DELETE, etc.)
- `url` (optional): URL della richiesta
- `payload` (optional): Payload della richiesta che ha triggato l'alert
- `user_agent` (optional): User-Agent del client

Risposta di successo (201):
```json
{
  "message": "False positive reported successfully",
  "entry": {
    "id": 3,
    "threat_type": "XSS",
    "client_ip": "192.168.1.100",
    "method": "POST",
    "url": "/api/comments",
    "payload": "comment=<b>This is bold text</b>",
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "status": "pending",
    "review_notes": null,
    "reviewed_by": null,
    "reviewed_at": null,
    "created_at": "2024-11-05T13:00:00Z",
    "updated_at": "2024-11-05T13:00:00Z"
  }
}
```

---

### 2.3 Aggiornare lo stato di un False Positive
**Metodo:** PATCH
**URL:** `/api/false-positives/:id`
**Header:** `Authorization: Bearer {token}`
**Body:** JSON

**Caso 1: Marcare come "reviewed" (revisionato)**
```bash
curl -X PATCH http://localhost:8080/api/false-positives/1 \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "status": "reviewed",
    "review_notes": "Legittimo - il formato HTML è consentito nei commenti"
  }'
```

**Caso 2: Marcare come "whitelisted" (auto-whitelistare l'IP)**
```bash
curl -X PATCH http://localhost:8080/api/false-positives/2 \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "status": "whitelisted",
    "review_notes": "Partner affidabile - aggiunto a whitelist automaticamente"
  }'
```

Parametri:
- `status` (required): Nuovo stato - "pending", "reviewed", o "whitelisted"
  - `pending`: In attesa di revisione
  - `reviewed`: Revisionato e confermato come falso positivo
  - `whitelisted`: Falso positivo - IP aggiunto automaticamente alla whitelist
- `review_notes` (optional): Note sulla revisione

Risposta di successo (200):
```json
{
  "message": "Status updated successfully"
}
```

**Nota importante:** Quando marchi uno status come "whitelisted", l'IP del client viene automaticamente aggiunto alla whitelist!

Errori possibili:
- `400` - Status non valido (accettati: "pending", "reviewed", "whitelisted")
- `404` - False positive non trovato

---

### 2.4 Eliminare un False Positive
**Metodo:** DELETE
**URL:** `/api/false-positives/:id`
**Header:** `Authorization: Bearer {token}`

```bash
curl -X DELETE http://localhost:8080/api/false-positives/1 \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Parametri URL:
- `id` (required): ID del false positive da eliminare

Risposta di successo (200):
```json
{
  "message": "Entry deleted successfully"
}
```

Errori possibili:
- `404` - False positive non trovato
- `500` - Errore del server

---

## 3. BLOCKLIST - Bloccare IP Dannosi

### 3.1 Recuperare la lista di IP bloccati
**Metodo:** GET
**URL:** `/api/blocklist`
**Header:** `Authorization: Bearer {token}`

```bash
curl -X GET http://localhost:8080/api/blocklist \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Risposta:
```json
{
  "blocked_ips": [
    {
      "id": 1,
      "ip_address": "203.0.113.10",
      "description": "Detect API Enumeration",
      "reason": "Blocked threat: Detect API Enumeration",
      "permanent": false,
      "expires_at": "2024-11-06T10:30:00Z",
      "created_at": "2024-11-05T10:30:00Z",
      "updated_at": "2024-11-05T10:30:00Z"
    }
  ],
  "count": 1
}
```

---

### 3.2 Bloccare un IP per una minaccia specifica
**Metodo:** POST
**URL:** `/api/blocklist`
**Header:** `Authorization: Bearer {token}`
**Body:** JSON

**Caso 1: Blocco temporaneo per 24 ore**
```bash
curl -X POST http://localhost:8080/api/blocklist \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "203.0.113.20",
    "threat": "XSS Attack Detected",
    "reason": "Multiple XSS attempts",
    "permanent": false,
    "duration_hours": 24
  }'
```

**Caso 2: Blocco permanente**
```bash
curl -X POST http://localhost:8080/api/blocklist \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "203.0.113.30",
    "threat": "Botnet Activity",
    "reason": "Confirmed botnet C2 server",
    "permanent": true
  }'
```

**Caso 3: Blocco custom per 7 giorni (168 ore)**
```bash
curl -X POST http://localhost:8080/api/blocklist \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "203.0.113.40",
    "threat": "SQL Injection Attempts",
    "reason": "Repeated SQL injection attempts",
    "permanent": false,
    "duration_hours": 168
  }'
```

Parametri:
- `ip` (required): Indirizzo IP da bloccare
- `threat` (required): Descrizione della minaccia
- `reason` (optional): Motivo del blocco
- `permanent` (optional): Se true, il blocco è permanente
- `duration_hours` (optional): Ore di blocco (se non permanente)

Risposta di successo (201):
```json
{
  "message": "IP blocked successfully",
  "blocked_ip": {
    "id": 5,
    "ip_address": "203.0.113.20",
    "description": "XSS Attack Detected",
    "reason": "Multiple XSS attempts",
    "permanent": false,
    "expires_at": "2024-11-06T16:00:00Z",
    "created_at": "2024-11-05T16:00:00Z",
    "updated_at": "2024-11-05T16:00:00Z"
  }
}
```

---

### 3.3 Sbloccare un IP
**Metodo:** DELETE
**URL:** `/api/blocklist/:ip`
**Header:** `Authorization: Bearer {token}`

```bash
curl -X DELETE http://localhost:8080/api/blocklist/203.0.113.20 \
  -H "Authorization: Bearer YOUR_TOKEN"
```

Parametri URL:
- `ip` (required): Indirizzo IP da sbloccare

Risposta di successo (200):
```json
{
  "message": "IP unblocked successfully"
}
```

---

## 4. Differenze Importanti

### Whitelist vs Blocklist

| Aspetto | Whitelist | Blocklist |
|---------|-----------|-----------|
| **Scopo** | IP affidabili che bypassano i controlli | IP dannosi da bloccare |
| **Effetto** | Permette il traffico anche se sospetto | Blocca il traffico |
| **Durata** | Permanente (nessuna scadenza) | Temporaneo o permanente |
| **Granularità** | Per IP semplice | Per IP + Minaccia (composita) |
| **Auto-creazione** | Tramite false positives | Tramite statistiche o manuale |

### False Positives vs Blocklist

- **False Positive**: Una minaccia che è stata identificata ma non è realmente una minaccia
- Quando marchi un false positive come "whitelisted", l'IP viene automaticamente aggiunto alla whitelist

---

## 5. Workflow Tipico

### Scenario 1: Ho un IP che viene bloccato ma è legittimo

1. Vedi l'avviso di blocco nella dashboard
2. Clicca su "Riporta come False Positive" oppure usa l'API:
   ```bash
   curl -X POST http://localhost:8080/api/false-positives \
     -H "Authorization: Bearer TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "threat_type": "XSS",
       "client_ip": "192.168.1.100",
       "method": "POST",
       "url": "/api/comments",
       "payload": "..."
     }'
   ```

3. Revisiona il report:
   ```bash
   curl -X PATCH http://localhost:8080/api/false-positives/1 \
     -H "Authorization: Bearer TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "status": "whitelisted",
       "review_notes": "Legittimo - partner affidabile"
     }'
   ```

4. L'IP è ora automaticamente nella whitelist!

---

### Scenario 2: Voglio bloccare manualmente un IP

```bash
curl -X POST http://localhost:8080/api/blocklist \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "203.0.113.50",
    "threat": "Brute Force Attack",
    "reason": "Tentativo di accesso multipli falliti",
    "permanent": false,
    "duration_hours": 72
  }'
```

---

### Scenario 3: Voglio aggiungere un partner alla whitelist

```bash
curl -X POST http://localhost:8080/api/whitelist \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ip_address": "203.0.113.100",
    "reason": "Partner API - integrazione pagamenti"
  }'
```

---

## 6. Note Importanti

1. **Token JWT**: Tutti gli endpoint richiedono autenticazione (tranne login)
2. **IP Address**: Può essere IPv4 o IPv6
3. **Duration Hours**: Numero intero di ore (es: 24, 48, 168)
4. **Status codes**:
   - `200`: OK
   - `201`: Created (POST)
   - `400`: Bad Request
   - `404`: Not Found
   - `409`: Conflict (IP già esiste)
   - `500`: Server Error

5. **Whitelist automatica**: Quando marchi un false positive come "whitelisted", il client IP viene automaticamente aggiunto alla whitelist!

6. **Composite key per Blocklist**: Un IP può essere bloccato per diverse minacce diverse - ogni combinazione (IP + minaccia) è unica!

