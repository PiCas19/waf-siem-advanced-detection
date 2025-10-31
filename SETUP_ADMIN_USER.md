# Setup Admin User

Questo documento contiene i comandi per creare un utente admin nel database SQLite.

## Info Utente
- **Email:** `pierpaolo.casati@student.supsi.ch`
- **Nome:** `Pierpaolo Casati`
- **Ruolo:** `admin`
- **Password Provvisoria:** `Password123!`

## Step 1: Creare l'utente nel database

Esegui questo comando sul webserver (sostituisci il percorso del database):

```bash
sqlite3 /home/caddy/data/waf.db << 'EOF'
INSERT INTO users (
  email,
  password_hash,
  name,
  role,
  active,
  two_fa_enabled,
  otp_secret,
  backup_codes,
  password_reset_token,
  password_reset_expiry,
  created_at,
  updated_at
)
VALUES (
  'pierpaolo.casati@student.supsi.ch',
  '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcg7b3XeKeUxWdeS86E36P4/GOe',
  'Pierpaolo Casati',
  'admin',
  1,
  0,
  '',
  '',
  '',
  NULL,
  datetime('now'),
  datetime('now')
);
EOF
```

## Step 2: Verificare che l'utente sia stato creato

```bash
sqlite3 /home/caddy/data/waf.db "SELECT id, email, name, role, active FROM users WHERE email='pierpaolo.casati@student.supsi.ch';"
```

Dovresti vedere:
```
1|pierpaolo.casati@student.supsi.ch|Pierpaolo Casati|admin|1
```

## Step 3: Login via API

Usa curl per testare il login:

```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "pierpaolo.casati@student.supsi.ch",
    "password": "Password123!"
  }'
```

Dovresti ricevere una risposta con il token JWT.

## Step 4: Accedere al Dashboard

1. Vai su `http://localhost:3000` (o il tuo dominio)
2. Login con:
   - **Email:** `pierpaolo.casati@student.supsi.ch`
   - **Password:** `Password123!`
3. Non avrà 2FA abilitato, quindi accederai direttamente
4. Poi puoi abilitare 2FA dalle settings dell'utente

## Troubleshooting

### Se ricevi "401 Unauthorized" al login:

1. Verifica che l'utente esista:
```bash
sqlite3 /home/caddy/data/waf.db "SELECT email, active FROM users WHERE email='pierpaolo.casati@student.supsi.ch';"
```

2. Verifica che `active = 1` (non `0`)

3. Aggiorna la password se necessario:
```bash
sqlite3 /home/caddy/data/waf.db << 'EOF'
UPDATE users
SET password_hash = '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcg7b3XeKeUxWdeS86E36P4/GOe',
    active = 1
WHERE email = 'pierpaolo.casati@student.supsi.ch';
EOF
```

4. Controlla che l'API stia girando sulla porta corretta (default: 8080)

### Se il login funziona ma il 2FA non funziona:

L'utente è stato creato senza 2FA abilitato. Puoi:
- Abilitarlo dalle settings del dashboard dopo il login
- Oppure usare il setup 2FA endpoint: `POST /api/auth/2fa/setup`

## Note

- La password hash sopra è il bcrypt hash di `Password123!`
- L'utente viene creato con `active = 1` così non deve fare il setup iniziale
- `two_fa_enabled = 0` così non deve verificare l'OTP al primo login
- Dopo il primo login, puoi cambiare la password dalle settings
