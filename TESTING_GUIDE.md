# Testing Guide - IP Quarantine Management

Questa guida ti mostra come testare le funzionalità di Blocklist, Whitelist e False Positives.

## Prerequisiti

1. Il WAF deve essere in esecuzione e configurato per inviare eventi al backend API
2. Il backend API deve essere in esecuzione
3. La dashboard deve essere in esecuzione
4. Devi essere loggato con un utente che ha i permessi di `blocklist_view`, `blocklist_block`, `blocklist_unblock`

## 1. Testing Blocklist (Blocco IP per minaccia)

### 1.1 Bloccare manualmente un IP dal tab Blocklist

**Passi:**
1. Apri la dashboard e vai al tab **"IP Quarantine Management"** → **Blocklist**
2. Clicca sul pulsante **"+ Block IP"** in alto a destra
3. Inserisci i seguenti dati:
   - **IP Address**: `192.168.1.100`
   - **Reason**: `Test manual block`
   - **Block Duration**: Seleziona una durata (es. "24 Hours", "7 Days", "Permanent", o "Custom")
   - Se scegli "Custom": inserisci `2` e seleziona "hours"
4. Clicca **"Block IP"**

**Risultato atteso:**
- Appare un toast: "IP blocked successfully"
- L'IP appare nella tabella Blocklist con la durata selezionata

### 1.2 Bloccare un IP da un alert in StatsPage

**Passi:**
1. Genera un attacco (vedi sezione 4.1)
2. Vai al tab **"Statistics"**
3. Nella tabella "Threat Detection Log", troverai il tuo alert
4. Clicca il pulsante **"Block"** per quella threat
5. Si aprirà un modal con le opzioni di durata
6. Seleziona la durata e clicca **"Confirm"**

**Risultato atteso:**
- L'alert cambia da "Block" a "Unblock"
- Appare un toast di successo
- L'IP viene aggiunto alla blocklist

### 1.3 Rimuovere un IP dalla Blocklist

**Passi:**
1. Nel tab **"IP Quarantine Management"** → **Blocklist**
2. Trova l'entry che hai appena creato
3. Clicca il pulsante **"Remove"** (con icona Trash)
4. Conferma la rimozione nel dialog

**Risultato atteso:**
- L'entry scompare dalla tabella (optimistic update)
- Appare un toast: "Entry removed successfully"
- Se torni a StatsPage, l'alert adesso mostra **"Block"** invece di "Unblock"

---

## 2. Testing Whitelist

### 2.1 Aggiungere manualmente un IP alla Whitelist

**Passi:**
1. Vai al tab **"IP Quarantine Management"** → **Whitelist**
2. Clicca **"+ Whitelist IP"**
3. Inserisci:
   - **IP Address**: `10.0.0.50`
   - **Reason**: `Test whitelist - trusted server`
4. Clicca **"Whitelist IP"**

**Risultato atteso:**
- Appare un toast: "IP whitelisted successfully"
- L'IP appare nella tabella Whitelist

### 2.2 Rimuovere un IP dalla Whitelist

**Passi:**
1. Nel tab Whitelist, trova l'entry
2. Clicca il pulsante **"Remove"** (icona Trash)
3. Conferma nel dialog

**Risultato atteso:**
- L'entry scompare dalla tabella
- Toast: "Entry removed successfully"

### 2.3 Effetto della Whitelist (Test del WAF)

**Come testare:**
1. Aggiungi un IP alla whitelist: `192.168.1.1`
2. Da un'altra macchina/terminale con IP `192.168.1.1`, invia una richiesta con payload XSS:
   ```bash
   curl -H "X-Forwarded-For: 192.168.1.1" \
     "http://localhost:8080/page?q=<script>alert('xss')</script>"
   ```
3. Controlla la dashboard

**Risultato atteso:**
- L'alert non appare in StatsPage (IP whitelisted, non viene loggato)
- L'IP non genera threat events anche con payload malevoli

---

## 3. Testing False Positives

### 3.1 Generare un alert che potrebbe essere un False Positive

**Passi:**
1. Genera un attacco sensato (vedi sezione 4.1 per XSS)
2. L'alert appare nel tab Statistics
3. Se pensi che sia un falso positivo, devi reportarlo

### 3.2 Come reportare un False Positive (Manuale via API)

Attualmente l'UI non ha un pulsante per reportare direttamente, ma puoi usare curl:

```bash
curl -X POST http://localhost:3000/api/false-positives \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "threat_type": "XSS",
    "client_ip": "192.168.1.100",
    "method": "GET",
    "url": "/page?q=<script>test</script>",
    "payload": "<script>test</script>",
    "user_agent": "Mozilla/5.0..."
  }'
```

**Oppure** se hai un database di test, inserisci direttamente:

```sql
INSERT INTO false_positives (threat_type, client_ip, method, url, status, created_at)
VALUES ('XSS', '192.168.1.150', 'GET', '/search?q=test', 'pending', NOW());
```

### 3.3 Gestire un False Positive nel tab False Positives

**Passi:**
1. Vai al tab **"IP Quarantine Management"** → **False Positives**
2. Vedrai le voci in stato "Pending"
3. Per ogni entry puoi:
   - Cliccare **"Mark as Reviewed"** - lo marchi come reviewed
   - Cliccare **"Whitelist IP"** - aggiungi l'IP alla whitelist e cambia status a "whitelisted"
   - Cliccare **"Delete"** - elimina il record del false positive

**Risultato atteso:**
- Lo status cambia di conseguenza nella tabella
- Se whitelisti, l'IP viene aggiunto anche al tab Whitelist
- Se elimini, il record scompare dalla lista

---

## 4. Attack Testing (Generare Minacce)

### 4.1 Test XSS (Cross-Site Scripting)

**Curl command:**
```bash
curl "http://localhost:8080/page?q=<script>alert('xss')</script>"
```

**In browser:**
```
http://localhost:8080/page?q=<script>alert('xss')</script>
```

**Risultato atteso:**
- Alert appare in Statistics → Threat Detection Log
- Threat Type: "XSS"
- Vedi i dettagli della richiesta (IP, User-Agent, Path)
- Puoi cliccare "Block" per bloccare quell'IP

### 4.2 Test SQL Injection

```bash
curl "http://localhost:8080/api/users?id=1' OR '1'='1"
```

**Risultato atteso:**
- Appare un alert con Threat Type: "SQL_INJECTION"

### 4.3 Test Path Traversal

```bash
curl "http://localhost:8080/files/../../etc/passwd"
```

**Risultato atteso:**
- Appare un alert con Threat Type: "PATH_TRAVERSAL"

### 4.4 Test con Custom Rules

Se hai creato custom rules, invia payload che matchano il pattern:

```bash
curl "http://localhost:8080/api/test?action=delete_all_users"
```

(Se hai una regola che matcha "delete_all")

---

## 5. Flow Completo - End to End Test

### Scenario: Bloccare un IP che fa attacchi

1. **Genera attacco**: Invia XSS da IP `192.168.1.200`
   ```bash
   curl -H "X-Forwarded-For: 192.168.1.200" \
     "http://localhost:8080/page?q=<script>bad</script>"
   ```

2. **Vedi l'alert**: Va in Statistics, vedi l'alert da `192.168.1.200` con threat "XSS"

3. **Blocca l'IP**: Clicca "Block" nel modal, seleziona "24 Hours"

4. **Verifica il blocco**: Prova a inviare un'altra richiesta da `192.168.1.200`
   ```bash
   curl -H "X-Forwarded-For: 192.168.1.200" \
     "http://localhost:8080/page?test=1"
   ```
   - **Risultato**: Richiesta riceve 403 Forbidden dal WAF

5. **Vai a Blocklist**: Nel tab "IP Quarantine Management" → Blocklist, vedi l'entry per `192.168.1.200` per la threat "XSS" con durata "24 Hours"

6. **Sblocca**: Clicca "Remove" per sbloccare

7. **Verifica sblocco**: Prova di nuovo la richiesta da `192.168.1.200`
   - **Risultato**: Ora passa attraverso (almeno questo alert, a meno che non generi un nuovo threat)

---

## 6. Troubleshooting

| Problema | Soluzione |
|----------|-----------|
| Non vedo alert in Statistics | Verifica che il WAF sia in esecuzione e invii gli eventi all'API |
| Non posso cliccare "Block" | Controlla di avere il permesso `threats_block` |
| L'IP non è bloccato dopo il blocco | Verifica che il WAF legga l'endpoint `/api/blocklist` |
| False Positive non appare nel tab | Verifica che sia stato creato via API o database |
| Whitelist non funziona | Controlla che il WAF middleware verifichi `IsIPWhitelisted()` prima di fare threat detection |

---

## 7. Testing Checklist

- [ ] Riesco a bloccare un IP manualmente dal tab Blocklist
- [ ] Riesco a scegliere la durata del blocco (24h, 7d, 30d, permanent, custom)
- [ ] Quando clicco "Remove" da Blocklist, l'IP è sbloccato
- [ ] Riesco a whitelistare un IP
- [ ] Quando rimuovo dalla whitelist, l'IP è tolto
- [ ] False positives possono essere marcati come "Reviewed" o "Whitelisted"
- [ ] Quando un IP è whitelisted da false positives, appare anche in Whitelist
- [ ] Riesco a bloccare un IP da un alert in Statistics
- [ ] La durata è calcolata correttamente nel blocco
- [ ] Tutti i toast di successo/errore funzionano
- [ ] Optimistic updates (il remove è immediato, poi ricarica)

---

## Note di Debugging

Se vuoi verificare il backend:

**Controlla gli IP bloccati:**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:3000/api/blocklist
```

**Controlla gli IP whitelisted:**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:3000/api/whitelist
```

**Controlla i False Positives:**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:3000/api/false-positives
```
