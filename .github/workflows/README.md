# GitHub Actions Workflows

Questa directory contiene i workflow CI/CD per il progetto WAF SIEM Advanced Detection.

## 📋 Workflows Disponibili

### 1. CI/CD Pipeline (`ci-cd.yml`)

**Trigger:**
- Push su branch: `main`, `dev`, `feature/*`
- Pull request verso: `main`, `dev`
- Creazione di release

**Stages:**

#### 📦 Install & Lint
- Setup Go 1.25 e Node.js 20
- Installazione dipendenze (API, WAF, Dashboard)
- Cache delle dipendenze per migliorare le prestazioni
- Lint del codice Dashboard

#### 🧪 Tests
Esegue test in parallelo per tutti i componenti:

- **Test API**:
  - Unit tests con race detection
  - Coverage report
  - Upload artifact coverage

- **Test WAF**:
  - Unit tests con race detection
  - Coverage report
  - Upload artifact coverage

- **Test Dashboard**:
  - Unit tests (Vitest)
  - Coverage report
  - E2E tests (Cypress) - commentato, abilitare se necessario

#### 🔨 Build
Compila binari multi-piattaforma:

- **API Server**:
  - Linux AMD64
  - macOS AMD64 (Intel)
  - macOS ARM64 (Apple Silicon)
  - Windows AMD64

- **WAF**:
  - Caddy con plugin WAF custom (multi-platform)
  - Coraza Forwarder (multi-platform)

- **Dashboard**:
  - Build ottimizzato con Vite
  - Asset statici pronti per il deployment

#### 📦 Package
Crea archivio distribuibile completo:

- Binari per tutte le piattaforme
- Dashboard buildato
- File di configurazione
- Script di deployment
- Documentazione
- Applicazioni di esempio

**Output:**
- `waf-siem-advanced-detection.tar.gz` (Linux/macOS)
- `waf-siem-advanced-detection.zip` (Windows)
- `checksums.txt` (SHA256)

#### 🚀 Deploy
**Trigger:** Solo su release o tag

- Upload automatico su GitHub Releases
- Include tutti gli artifact
- Release notes automatiche

---

### 2. Security Scanning (`security.yml`)

**Trigger:**
- Push su `main`, `dev`
- Pull request
- Schedule giornaliero (2 AM UTC)

**Scansioni:**

#### 🔒 Go Security (gosec)
- Scansione statica codice Go (API + WAF)
- Upload risultati in formato SARIF
- Integrazione con GitHub Security

#### 🛡️ Vulnerability Check (govulncheck)
- Verifica vulnerabilità dipendenze Go
- Database vulnerabilità ufficiale Go

#### 📊 NPM Audit
- Audit dipendenze Dashboard
- Controllo vulnerabilità critical/moderate

#### 🔍 CodeQL Analysis
- SAST (Static Application Security Testing)
- Analisi Go e JavaScript/TypeScript
- Integrazione GitHub Advanced Security

#### 🔑 Secret Detection (TruffleHog)
- Scansione segreti nel codice
- Verifica credenziali hardcoded
- Solo segreti verificati

---

### 3. Dependency Management (`dependencies.yml`)

**Trigger:**
- Schedule settimanale (Lunedì 9 AM UTC)
- Manuale (workflow_dispatch)

**Funzioni:**

#### 📈 Update Check
- Verifica aggiornamenti Go modules
- Verifica aggiornamenti NPM packages
- Report pacchetti obsoleti

#### 📊 Dependency Graph
- Aggiornamento grafo dipendenze
- Integrazione GitHub Dependency Graph
- Supporto Dependabot

---

## 🚀 Come Usare i Workflows

### Sviluppo Normale
```bash
git checkout -b feature/nuova-funzionalita
# ... sviluppo ...
git push origin feature/nuova-funzionalita
```
Il workflow CI/CD si attiverà automaticamente.

### Creare una Release

#### Opzione 1: GitHub Release UI
1. Vai su GitHub → Releases → "Draft a new release"
2. Crea un nuovo tag (es. `v1.0.0`)
3. Pubblica la release
4. Il workflow creerà e caricherà automaticamente gli artifact

#### Opzione 2: Git Tag
```bash
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0
```

### Eseguire Security Scan Manualmente
```bash
# Vai su GitHub → Actions → Security Scanning → Run workflow
```

### Verificare Dipendenze Obsolete
```bash
# Vai su GitHub → Actions → Dependency Management → Run workflow
```

---

## 📊 Artifact e Reports

### Artifact Temporanei (7 giorni)
- `api-coverage` - Coverage report API
- `waf-coverage` - Coverage report WAF
- `dashboard-coverage` - Coverage report Dashboard
- `api-binaries` - Binari compilati API
- `waf-binaries` - Binari compilati WAF
- `dashboard-build` - Build dashboard

### Artifact Release (30 giorni)
- `release-package-tar` - Package completo (.tar.gz)
- `release-package-zip` - Package completo (.zip)
- `checksums` - Checksum SHA256

### Security Reports
Disponibili in: **Security → Code scanning alerts**

---

## ⚙️ Configurazione

### Variabili d'Ambiente
Definite nel workflow `ci-cd.yml`:
- `GO_VERSION: '1.25'`
- `NODE_VERSION: '20'`

### Secrets Richiesti
Nessun secret aggiuntivo richiesto. Il workflow usa:
- `GITHUB_TOKEN` (fornito automaticamente)

### Abilitare E2E Tests
Nel file `ci-cd.yml`, decommentare il job `test-dashboard-e2e`:
```yaml
test-dashboard-e2e:
  name: Test Dashboard E2E (Cypress)
  # ... resto del job
```

---

## 🔧 Manutenzione

### Aggiornare Versioni Go/Node
Modificare le variabili d'ambiente in `ci-cd.yml`:
```yaml
env:
  GO_VERSION: '1.26'  # Nuova versione
  NODE_VERSION: '22'   # Nuova versione
```

### Aggiungere Nuove Piattaforme
Nel job `build-api` o `build-waf`, aggiungere:
```yaml
- name: Build for new platform
  run: |
    GOOS=freebsd GOARCH=amd64 go build -o bin/app-freebsd-amd64 ./cmd/app
```

### Modificare Schedule
Cambiare cron expression:
```yaml
schedule:
  - cron: '0 3 * * *'  # Esempio: 3 AM UTC ogni giorno
```

---

## 📈 Best Practices

1. **Branch Protection**: Configura branch protection su `main`:
   - Require status checks to pass
   - Require tests to pass prima del merge

2. **Code Owners**: Crea un file `.github/CODEOWNERS` per review obbligatorie

3. **Dependabot**: Abilita Dependabot per aggiornamenti automatici:
   ```yaml
   # .github/dependabot.yml
   version: 2
   updates:
     - package-ecosystem: "gomod"
       directory: "/api"
       schedule:
         interval: "weekly"
   ```

4. **Status Badges**: Aggiungi badge nel README:
   ```markdown
   ![CI/CD](https://github.com/username/repo/actions/workflows/ci-cd.yml/badge.svg)
   ![Security](https://github.com/username/repo/actions/workflows/security.yml/badge.svg)
   ```

---

## 🐛 Troubleshooting

### I test falliscono in CI ma passano localmente
- Verifica differenze ambiente (timezone, locale, filesystem)
- Controlla race conditions con `-race` flag
- Usa cache consistente con `actions/cache`

### Build fallisce per dipendenze
- Verifica `go.sum` sia committato
- Assicurati che `package-lock.json` sia aggiornato
- Prova a pulire cache: rimuovi cache key e riprova

### Artifact troppo grandi
- Abilita compressione UPX per binari Go
- Usa `go build -ldflags="-s -w"` per stripping
- Ottimizza build Vite con tree-shaking

---

## 📚 Risorse

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Go CI/CD Best Practices](https://github.com/mvdan/github-actions-golang)
- [Node.js CI/CD Guide](https://docs.github.com/en/actions/automating-builds-and-tests/building-and-testing-nodejs)
- [Security Hardening for GitHub Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
