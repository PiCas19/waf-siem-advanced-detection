# API Reference

Complete API documentation for the WAF-SIEM Advanced Detection Backend.

## Base URL

```
http://localhost:8081/api
```

## Authentication

Most endpoints require JWT authentication. Include the token in the `Authorization` header:

```
Authorization: Bearer <your-jwt-token>
```

## Response Format

All responses follow this structure:

```json
{
  "success": true,
  "message": "Operation successful",
  "data": { ... }
}
```

Error responses:

```json
{
  "success": false,
  "message": "Error description",
  "error": "Detailed error information"
}
```

---

## Public Endpoints

### Authentication

#### Login
```http
POST /api/auth/login
```

**Request Body:**
```json
{
  "email": "admin@example.com",
  "password": "your-password"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user": {
      "id": 1,
      "email": "admin@example.com",
      "role": "admin",
      "two_factor_enabled": false
    }
  }
}
```

#### Verify OTP (Two-Factor Authentication)
```http
POST /api/auth/verify-otp
```

**Request Body:**
```json
{
  "email": "admin@example.com",
  "otp_code": "123456"
}
```

#### Set Password with Token
```http
POST /api/auth/set-password
```

Used for setting password after user invitation or password reset.

**Request Body:**
```json
{
  "token": "invitation-or-reset-token",
  "new_password": "new-secure-password"
}
```

#### Forgot Password
```http
POST /api/auth/forgot-password
```

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

#### Reset Password
```http
POST /api/auth/reset-password
```

**Request Body:**
```json
{
  "token": "reset-token-from-email",
  "new_password": "new-secure-password"
}
```

### WAF Integration Endpoints

#### Submit WAF Event
```http
POST /api/waf/event
```

Used by WAF middleware to send security events to the backend.

**Request Body:**
```json
{
  "timestamp": "2025-12-19T10:00:00Z",
  "client_ip": "192.168.1.100",
  "method": "GET",
  "url": "/search?q=<script>alert(1)</script>",
  "threat_type": "XSS",
  "severity": "high",
  "payload": "<script>alert(1)</script>",
  "action_taken": "blocked"
}
```

#### Get Custom Rules for WAF
```http
GET /api/waf/custom-rules
```

Returns custom detection rules for the WAF middleware.

**Response:**
```json
{
  "success": true,
  "data": {
    "rules": [
      {
        "id": 1,
        "name": "Block SQL Keywords",
        "pattern": "(?i)(union|select|insert|drop|delete).*from",
        "severity": "high",
        "enabled": true
      }
    ]
  }
}
```

#### Get Blocklist for WAF
```http
GET /api/waf/blocklist
```

Returns list of blocked IPs for WAF middleware.

**Response:**
```json
{
  "success": true,
  "data": {
    "blocked_ips": [
      {
        "ip": "192.168.1.100",
        "reason": "Multiple XSS attempts",
        "expires_at": "2025-12-20T10:00:00Z"
      }
    ]
  }
}
```

#### Get Whitelist for WAF
```http
GET /api/waf/whitelist
```

Returns whitelisted IPs/networks.

**Response:**
```json
{
  "success": true,
  "data": {
    "whitelisted": [
      {
        "id": 1,
        "ip_address": "192.168.1.0/24",
        "description": "Internal network"
      }
    ]
  }
}
```

#### Verify Challenge
```http
POST /api/waf/challenge/verify
```

Verify Cloudflare Turnstile challenge token.

**Request Body:**
```json
{
  "token": "cloudflare-turnstile-token",
  "client_ip": "192.168.1.100"
}
```

---

## Protected Endpoints

### Statistics

#### Get Dashboard Stats
```http
GET /api/stats
```

**Headers:** `Authorization: Bearer <token>`

**Response:**
```json
{
  "success": true,
  "data": {
    "total_requests": 10523,
    "threats_detected": 127,
    "threats_blocked": 95,
    "blocked_ips": 12,
    "active_rules": 105
  }
}
```

#### Get Geolocation Data
```http
GET /api/geolocation
```

**Headers:** `Authorization: Bearer <token>`

Returns geographic distribution of threats.

### Rules Management

#### List Rules
```http
GET /api/rules
```

**Headers:** `Authorization: Bearer <token>`

**Query Parameters:**
- `page` (int): Page number (default: 1)
- `limit` (int): Items per page (default: 50)
- `search` (string): Search by name or pattern

**Response:**
```json
{
  "success": true,
  "data": {
    "rules": [
      {
        "id": 1,
        "name": "XSS Detection",
        "pattern": "<script.*?>",
        "severity": "high",
        "enabled": true,
        "type": "custom",
        "created_at": "2025-12-15T10:00:00Z"
      }
    ],
    "total": 105,
    "page": 1,
    "limit": 50
  }
}
```

#### Create Rule
```http
POST /api/rules
```

**Headers:** `Authorization: Bearer <token>`

**Request Body:**
```json
{
  "name": "Detect SQL Injection",
  "pattern": "(?i)(union|select).*from",
  "severity": "critical",
  "enabled": true,
  "description": "Detects common SQL injection patterns"
}
```

**Severity Levels:** `low`, `medium`, `high`, `critical`

#### Update Rule
```http
PUT /api/rules/:id
```

**Headers:** `Authorization: Bearer <token>`

**Request Body:** (same as Create Rule)

#### Delete Rule
```http
DELETE /api/rules/:id
```

**Headers:** `Authorization: Bearer <token>`

#### Toggle Rule Status
```http
PATCH /api/rules/:id/toggle
```

**Headers:** `Authorization: Bearer <token>`

Enables or disables a rule.

### Logs Management

#### Get Logs
```http
GET /api/logs
```

**Headers:** `Authorization: Bearer <token>`

**Query Parameters:**
- `page` (int): Page number
- `limit` (int): Items per page
- `severity` (string): Filter by severity
- `threat_type` (string): Filter by threat type
- `start_date` (ISO8601): Start date
- `end_date` (ISO8601): End date
- `client_ip` (string): Filter by IP

**Response:**
```json
{
  "success": true,
  "data": {
    "logs": [
      {
        "id": 1,
        "timestamp": "2025-12-19T10:00:00Z",
        "client_ip": "192.168.1.100",
        "country": "IT",
        "method": "GET",
        "url": "/api/search?q=<script>alert(1)</script>",
        "threat_type": "XSS",
        "severity": "high",
        "payload": "<script>alert(1)</script>",
        "action_taken": "blocked",
        "rule_matched": "Default XSS Rule #5"
      }
    ],
    "total": 1523,
    "page": 1,
    "limit": 50
  }
}
```

#### Update Threat Block Status
```http
PUT /api/logs/threat-status
```

**Headers:** `Authorization: Bearer <token>`

**Request Body:**
```json
{
  "log_id": 123,
  "is_blocked": true
}
```

### Audit Logs

#### Get Audit Logs
```http
GET /api/audit-logs
```

**Headers:** `Authorization: Bearer <token>`

Returns user activity audit logs.

**Query Parameters:**
- `page`, `limit`, `start_date`, `end_date`

#### Get Audit Log Statistics
```http
GET /api/audit-logs/stats
```

**Headers:** `Authorization: Bearer <token>`

Returns statistics about user actions.

### Blocklist Management

#### Get Blocklist
```http
GET /api/blocklist
```

**Headers:** `Authorization: Bearer <token>`

**Query Parameters:**
- `page` (int)
- `limit` (int)

#### Block IP
```http
POST /api/blocklist
```

**Headers:** `Authorization: Bearer <token>`

**Required Permission:** `blocklist_add`

**Request Body:**
```json
{
  "ip": "192.168.1.100",
  "reason": "Multiple XSS attempts",
  "duration": 3600,
  "create_rule": true
}
```

**Parameters:**
- `ip` (string): IP address to block
- `reason` (string): Reason for blocking
- `duration` (int): Block duration in seconds (0 = permanent)
- `create_rule` (bool): Create a manual block rule in WAF

#### Unblock IP
```http
DELETE /api/blocklist/:ip
```

**Headers:** `Authorization: Bearer <token>`

**Required Permission:** `blocklist_remove`

### Whitelist Management

#### Get Whitelist
```http
GET /api/whitelist
```

**Headers:** `Authorization: Bearer <token>`

#### Add to Whitelist
```http
POST /api/whitelist
```

**Headers:** `Authorization: Bearer <token>`

**Required Permission:** `whitelist_add`

**Request Body:**
```json
{
  "ip_address": "192.168.1.0/24",
  "description": "Internal corporate network"
}
```

#### Remove from Whitelist
```http
DELETE /api/whitelist/:id
```

**Headers:** `Authorization: Bearer <token>`

**Required Permission:** `whitelist_remove`

### False Positives

#### Get False Positives
```http
GET /api/false-positives
```

**Headers:** `Authorization: Bearer <token>`

#### Report False Positive
```http
POST /api/false-positives
```

**Headers:** `Authorization: Bearer <token>`

**Required Permission:** `false_positives_report`

**Request Body:**
```json
{
  "log_id": 123,
  "reason": "Legitimate SQL query in URL parameter",
  "suggested_fix": "Whitelist this specific URL pattern"
}
```

#### Update False Positive Status
```http
PATCH /api/false-positives/:id
```

**Headers:** `Authorization: Bearer <token>`

**Required Permission:** `false_positives_resolve`

**Request Body:**
```json
{
  "status": "resolved",
  "resolution_notes": "Added URL to whitelist"
}
```

#### Delete False Positive
```http
DELETE /api/false-positives/:id
```

**Headers:** `Authorization: Bearer <token>`

**Required Permission:** `false_positives_delete`

### Two-Factor Authentication

#### Setup 2FA
```http
POST /api/auth/2fa/setup
```

**Headers:** `Authorization: Bearer <token>`

**Response:**
```json
{
  "success": true,
  "data": {
    "qr_code": "data:image/png;base64,...",
    "secret": "JBSWY3DPEHPK3PXP"
  }
}
```

#### Confirm 2FA Setup
```http
POST /api/auth/2fa/confirm
```

**Headers:** `Authorization: Bearer <token>`

**Request Body:**
```json
{
  "otp_code": "123456"
}
```

#### Disable 2FA
```http
POST /api/auth/2fa/disable
```

**Headers:** `Authorization: Bearer <token>`

**Request Body:**
```json
{
  "password": "current-password"
}
```

### Password Management

#### Change Password
```http
POST /api/auth/change-password
```

**Headers:** `Authorization: Bearer <token>`

**Request Body:**
```json
{
  "current_password": "old-password",
  "new_password": "new-secure-password"
}
```

### Export Endpoints

#### Export Logs
```http
GET /api/export/logs?format=csv
```

**Headers:** `Authorization: Bearer <token>`

**Query Parameters:**
- `format` (string): `json`, `csv`, or `pdf`
- All filter parameters from GET /api/logs

#### Export Audit Logs
```http
GET /api/export/audit-logs?format=json
```

**Headers:** `Authorization: Bearer <token>`

**Query Parameters:**
- `format` (string): `json`, `csv`, or `pdf`

#### Export Blocklist
```http
GET /api/export/blocklist?format=csv
```

**Headers:** `Authorization: Bearer <token>`

**Query Parameters:**
- `format` (string): `json` or `csv`

---

## Admin Endpoints

All admin endpoints require both authentication AND admin role.

### User Management

#### List Users
```http
GET /api/admin/users
```

**Headers:** `Authorization: Bearer <admin-token>`

**Response:**
```json
{
  "success": true,
  "data": {
    "users": [
      {
        "id": 1,
        "email": "admin@example.com",
        "role": "admin",
        "two_factor_enabled": true,
        "created_at": "2025-12-01T10:00:00Z",
        "last_login": "2025-12-19T09:30:00Z"
      }
    ]
  }
}
```

#### Create User (Admin Invite)
```http
POST /api/admin/users
```

**Headers:** `Authorization: Bearer <admin-token>`

**Request Body:**
```json
{
  "email": "newuser@example.com",
  "role": "analyst"
}
```

**Roles:**
- `admin`: Full access
- `analyst`: Read/write access to logs, rules, blocklist
- `viewer`: Read-only access

An invitation email will be sent to the user.

#### Update User
```http
PUT /api/admin/users/:id
```

**Headers:** `Authorization: Bearer <admin-token>`

**Request Body:**
```json
{
  "email": "updated@example.com",
  "role": "analyst"
}
```

#### Delete User
```http
DELETE /api/admin/users/:id
```

**Headers:** `Authorization: Bearer <admin-token>`

---

## WebSocket Connection

Real-time threat notifications via WebSocket.

```
ws://localhost:8081/ws
```

**Connection:** Include JWT token as query parameter:
```
ws://localhost:8081/ws?token=<your-jwt-token>
```

**Message Format:**
```json
{
  "type": "threat_detected",
  "data": {
    "timestamp": "2025-12-19T10:00:00Z",
    "client_ip": "192.168.1.100",
    "threat_type": "XSS",
    "severity": "high",
    "url": "/api/search?q=<script>alert(1)</script>"
  }
}
```

---

## Rate Limiting

API endpoints are rate limited:
- Public endpoints: 60 requests/minute per IP
- Protected endpoints: 300 requests/minute per user
- Admin endpoints: 100 requests/minute per admin

**Rate Limit Headers:**
```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1703001600
```

---

## Error Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 201 | Created |
| 400 | Bad Request (validation error) |
| 401 | Unauthorized (missing/invalid token) |
| 403 | Forbidden (insufficient permissions) |
| 404 | Not Found |
| 409 | Conflict (duplicate entry) |
| 429 | Too Many Requests (rate limit exceeded) |
| 500 | Internal Server Error |

---

## Permissions

| Permission | Required Role | Description |
|-----------|---------------|-------------|
| `blocklist_add` | analyst, admin | Add IP to blocklist |
| `blocklist_remove` | analyst, admin | Remove IP from blocklist |
| `whitelist_add` | admin | Add IP to whitelist |
| `whitelist_remove` | admin | Remove IP from whitelist |
| `false_positives_report` | analyst, admin | Report false positive |
| `false_positives_resolve` | admin | Resolve false positive |
| `false_positives_delete` | admin | Delete false positive |
