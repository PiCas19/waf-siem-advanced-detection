# Cypress E2E Tests for WAF Dashboard

Questo progetto contiene test end-to-end completi per la dashboard WAF usando Cypress.

## Struttura dei Test

```
cypress/
├── e2e/
│   ├── auth.cy.ts           # Test di autenticazione (login, 2FA, password reset)
│   ├── dashboard.cy.ts       # Test di navigazione e funzionalità dashboard
│   └── user-flows.cy.ts      # Test di flussi utente completi end-to-end
├── support/
│   ├── commands.ts           # Custom commands riutilizzabili
│   └── e2e.ts               # Setup globale
└── README.md                 # Questa guida
```

## Test Coverage

### 1. Authentication Tests (`auth.cy.ts`)
- ✅ Login con email e password
- ✅ Validazione form di login
- ✅ Gestione errori credenziali invalide
- ✅ Password reset/forgot password
- ✅ Set password per nuovi utenti
- ✅ Toggle mostra/nascondi password
- ✅ 2FA verification flow
- ✅ Logout e rimozione token
- ✅ Protected routes (redirect a login)
- ✅ Session expiration handling

### 2. Dashboard Tests (`dashboard.cy.ts`)
- ✅ Navigazione tra tabs (Statistics, Rules, Logs, Blocklist, Users)
- ✅ Visualizzazione statistiche in tempo reale
- ✅ World map con distribuzione geografica attacchi
- ✅ Grafici e charts con trends
- ✅ Gestione regole WAF (CRUD operations)
- ✅ Toggle enable/disable regole
- ✅ Visualizzazione e filtraggio logs
- ✅ Paginazione logs
- ✅ Gestione blocklist (add/remove IP)
- ✅ Whitelist e false positives
- ✅ User management (solo admin)
- ✅ Responsive design (mobile, tablet, desktop)
- ✅ Real-time updates via WebSocket
- ✅ Error handling (API errors, network errors)

### 3. User Flows Tests (`user-flows.cy.ts`)
- ✅ First time user complete flow (password setup + 2FA)
- ✅ WAF rule management complete flow
- ✅ Threat detection and response flow
- ✅ False positive management flow
- ✅ Security analyst daily workflow
- ✅ Admin user management flow
- ✅ Error recovery flow (session expiration, API errors)

## Custom Commands

### `cy.clearStorage()`
Pulisce localStorage, sessionStorage e cookies.

```typescript
cy.clearStorage();
```

### `cy.setAuthToken(token: string)`
Imposta il token di autenticazione in localStorage.

```typescript
cy.setAuthToken('fake-jwt-token');
```

### `cy.login(email: string, password: string)`
Esegue il login con email e password.

```typescript
cy.login('admin@test.com', 'password123');
```

### `cy.mockDashboardAPIs()`
Mocka tutte le API comuni della dashboard.

```typescript
cy.mockDashboardAPIs();
```

## Esecuzione dei Test

### Prerequisiti
```bash
npm install
```

### ⚠️ IMPORTANTE: Il Server Deve Essere Avviato

I test Cypress richiedono che il server di sviluppo sia in esecuzione su `http://localhost:3000`.

### Metodo 1: Automatico (Raccomandato) ✅

Questi script avviano automaticamente il server e poi i test:

#### Modalità Interattiva (Cypress UI)
```bash
npm run test:e2e:open
```

Questo comando:
1. Avvia il server Vite su http://localhost:3000
2. Attende che il server sia pronto
3. Apre la Cypress UI

Nella UI puoi:
- Selezionare quale test eseguire
- Vedere i test in esecuzione in tempo reale
- Debuggare facilmente i fallimenti
- Time travel attraverso gli step del test

#### Modalità Headless (CI/CD)
```bash
npm run test:e2e
```

Esegue tutti i test in modalità headless, ideale per:
- CI/CD pipelines
- Test automatici prima del commit
- Verifiche veloci

#### Modalità Headed (Con Browser Visibile)
```bash
npm run test:e2e:headed
```

#### Eseguire Tutti i Test (Vitest + Cypress)
```bash
npm run test:all
```

### Metodo 2: Manuale

Se preferisci controllare manualmente il server:

**Terminal 1 - Avvia il server:**
```bash
npm run dev
```

**Terminal 2 - Esegui i test:**
```bash
# Modalità UI
npm run cypress:open

# Modalità headless
npm run cypress:run
```

### Eseguire un Singolo Test
```bash
# Con server automatico
npm run test:e2e -- --spec "cypress/e2e/auth.cy.ts"

# Con server manuale (se già avviato)
npm run cypress:run -- --spec "cypress/e2e/auth.cy.ts"
```

### Eseguire Test per Browser Specifico
```bash
npm run cypress:run -- --browser chrome
npm run cypress:run -- --browser firefox
npm run cypress:run -- --browser edge
```

### Con Video Recording
```bash
npm run cypress:run -- --video
```

### Con Screenshot dei Fallimenti
```bash
npm run cypress:run -- --screenshot-on-run-failure
```

## Configurazione

La configurazione si trova in `cypress.config.ts`:

```typescript
export default defineConfig({
  e2e: {
    baseUrl: 'http://localhost:3000',  // URL della dashboard
    viewportWidth: 1280,
    viewportHeight: 720,
    video: false,
    screenshotOnRunFailure: true,
  },
});
```

## Best Practices

### 1. Mock API Responses
I test usano `cy.intercept()` per mockare le risposte API:

```typescript
cy.intercept('GET', '/api/stats', {
  statusCode: 200,
  body: { threats_detected: 250 }
}).as('getStats');
```

### 2. Wait for API Calls
Usa `cy.wait()` per attendere le chiamate API:

```typescript
cy.wait('@getStats');
```

### 3. Use Data Test IDs (quando possibile)
```typescript
cy.get('[data-testid="login-button"]').click();
```

### 4. Avoid Hard-coded Timeouts
Usa `waitFor` invece di `cy.wait(5000)`:

```typescript
cy.contains('Success', { timeout: 5000 }).should('be.visible');
```

### 5. Clean State Before Each Test
```typescript
beforeEach(() => {
  cy.clearStorage();
  cy.setAuthToken('fake-token');
  cy.mockDashboardAPIs();
});
```

## Debugging

### Cypress Debug Mode
```bash
DEBUG=cypress:* npm run cypress:run
```

### Pause Test Execution
```typescript
cy.pause();
```

### Screenshot Specific Moment
```typescript
cy.screenshot('nome-screenshot');
```

### Console Logs
```typescript
cy.window().then((win) => {
  console.log(win.localStorage.getItem('authToken'));
});
```

## CI/CD Integration

### GitHub Actions Example
```yaml
name: E2E Tests

on: [push, pull_request]

jobs:
  cypress-run:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v3

      - name: Setup Node
        uses: actions/setup-node@v3
        with:
          node-version: '18'

      - name: Install dependencies
        run: npm ci

      - name: Start dev server
        run: npm run dev &

      - name: Wait for server
        run: npx wait-on http://localhost:3000

      - name: Run Cypress tests
        run: npm run cypress:run

      - name: Upload screenshots
        uses: actions/upload-artifact@v3
        if: failure()
        with:
          name: cypress-screenshots
          path: cypress/screenshots
```

## Troubleshooting

### Test Timeout
Se i test vanno in timeout, aumenta il timeout globale:
```typescript
Cypress.config('defaultCommandTimeout', 10000);
```

### WebSocket Connection Issues
Assicurati che il server di sviluppo supporti WebSocket:
```bash
npm run dev -- --host
```

### CORS Errors
Configura il proxy in `vite.config.ts`:
```typescript
server: {
  proxy: {
    '/api': 'http://localhost:8080'
  }
}
```

## Note Importanti

1. **Token Storage**: L'app usa `authToken` (non `token`) in localStorage
2. **Login**: Usa `email` (non `username`) per il login
3. **Dashboard Structure**: Usa tabs invece di rotte separate
4. **API Responses**:
   - Blocklist/Whitelist: `{ items: [...] }`
   - False Positives: `{ false_positives: [...] }`
   - Users: `{ data: [...] }`

## Contribuire

Quando aggiungi nuovi test:
1. Segui la struttura esistente
2. Usa i custom commands quando possibile
3. Mocka sempre le API responses
4. Aggiungi commenti per flussi complessi
5. Testa su multiple viewport sizes

## Contatti e Supporto

Per problemi o domande sui test, consulta:
- Documentazione Cypress: https://docs.cypress.io
- Repository del progetto: [link]
