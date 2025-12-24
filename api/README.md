# WAF API Backend

Enterprise-grade RESTful API backend for WAF dashboard with comprehensive security features, JWT authentication, and advanced database management.

## Features

### Authentication & Security
- JWT-based authentication with refresh tokens
- OTP (One-Time Password) support for 2FA
- Rate limiting and request throttling
- CORS middleware
- Circuit breaker pattern for resilience

### WAF Management
- **Rules Management** - CRUD operations for custom WAF rules
- **Default Rules** - Built-in detection rules management
- **IP Blocklist** - Dynamic IP blocking and unblocking
- **IP Whitelist** - Trusted IP management
- **Trusted Sources** - Manage trusted network sources
- **False Positives** - Track and manage false positive detections
- **Manual Blocking** - Priority-based manual block rules

### Monitoring & Analytics
- **Security Logs** - Comprehensive logging with filtering and pagination
- **Audit Logs** - Track all administrative actions
- **Statistics Dashboard** - Real-time threat statistics and trends
- **GeoIP** - IP geolocation tracking
- **Threat Intelligence** - Integration with threat intelligence feeds

### Data Management
- **Export Functionality** - Export logs in JSON, CSV, and PDF formats
- **WebSocket Support** - Real-time alerts and notifications
- **Pagination** - Efficient data pagination for large datasets
- **Advanced Filtering** - Multi-criteria search and filtering

### Infrastructure
- **Worker Pool** - Background job processing
- **Job Queue** - Asynchronous task management
- **Caching** - In-memory caching for performance
- **Email Notifications** - Alert system via email

## Installation
```bash
cd api
go mod download
```

## Running
```bash
go run cmd/api-server/main.go
```

API will be available at `http://localhost:8081`

## API Endpoints

### Public Endpoints
- `POST /api/auth/login` - User login
- `POST /api/auth/register` - User registration
- `GET /health` - Health check endpoint

### Authentication Endpoints (Protected)
- `POST /api/auth/refresh` - Refresh JWT token
- `POST /api/auth/logout` - User logout
- `POST /api/auth/otp/generate` - Generate OTP for 2FA
- `POST /api/auth/otp/verify` - Verify OTP token

### Dashboard & Statistics
- `GET /api/stats` - Dashboard statistics and metrics
- `GET /api/stats/trends` - Attack trends over time

### WAF Rules Management
- `GET /api/rules` - List custom WAF rules
- `POST /api/rules` - Create new custom rule
- `PUT /api/rules/:id` - Update rule
- `DELETE /api/rules/:id` - Delete rule
- `GET /api/default-rules` - List built-in default rules
- `PUT /api/default-rules/:id` - Toggle default rule status

### Security Logs
- `GET /api/logs` - Get security event logs (with pagination & filtering)
- `POST /api/logs/manual` - Create manual log entry
- `GET /api/logs/export` - Export logs (JSON/CSV/PDF)
- `DELETE /api/logs/:id` - Delete log entry

### IP Management
- `GET /api/blocklist` - Get blocked IPs
- `POST /api/blocklist` - Block IP address
- `DELETE /api/blocklist/:id` - Remove IP from blocklist
- `GET /api/whitelist` - Get whitelisted IPs
- `POST /api/whitelist` - Add IP to whitelist
- `DELETE /api/whitelist/:id` - Remove IP from whitelist
- `GET /api/trusted-sources` - Get trusted network sources
- `POST /api/trusted-sources` - Add trusted source

### False Positives & Audit
- `GET /api/false-positives` - List false positive detections
- `POST /api/false-positives` - Report false positive
- `PUT /api/false-positives/:id` - Update false positive status
- `GET /api/audit-logs` - Get audit trail of administrative actions

### Real-time Communication
- `WS /ws` - WebSocket endpoint for real-time alerts

### Admin Endpoints (Admin Role Required)
- `GET /api/admin/users` - List all users
- `DELETE /api/admin/users/:id` - Delete user
- `PUT /api/admin/users/:id/role` - Update user role

## Database

Default: SQLite (`waf.db`) - PostgreSQL compatible

### Database Models

- **User** - Dashboard users with roles (admin, user)
- **Rule** - Custom WAF detection rules (regex-based)
- **Log** - Security event logs with threat details
- **BlockedIP** - IP blocklist with reason and timestamp
- **WhitelistedIP** - Whitelisted IPs for bypass
- **TrustedSource** - Trusted network sources (Tailscale, VPN, etc.)
- **FalsePositive** - False positive tracking and resolution
- **AuditLog** - Administrative action audit trail

### Architecture

The API follows a clean architecture pattern:
```
cmd/
  └── api-server/      # Application entry point
internal/
  ├── api/             # HTTP handlers
  ├── auth/            # Authentication & JWT
  ├── database/        # Database connection & migrations
  │   └── models/      # Data models
  ├── repository/      # Data access layer
  ├── service/         # Business logic layer
  ├── middleware/      # HTTP middleware (CORS, rate limit, etc.)
  ├── websocket/       # WebSocket hub for real-time alerts
  ├── geoip/           # GeoIP service
  ├── threatintel/     # Threat intelligence integration
  ├── worker/          # Background job processing
  └── mailer/          # Email notification service
```

## Environment Variables

Create a `.env` file based on `.env.template`:

```bash
# Server Configuration
PORT=8081
HOST=0.0.0.0

# Database
DATABASE_URL=waf.db
# Or for PostgreSQL:
# DATABASE_URL=postgresql://user:password@localhost:5432/waf_db

# JWT Authentication
JWT_SECRET=your-secret-key-change-in-production
JWT_EXPIRATION=24h
JWT_REFRESH_EXPIRATION=168h

# Security
CORS_ORIGINS=http://localhost:3000,http://localhost:8080
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_DURATION=1m

# Email (Optional - for notifications)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM=WAF Alert System <noreply@yourwaf.com>

# GeoIP (Optional)
GEOIP_ENABLED=true
GEOIP_DB_PATH=/path/to/GeoLite2-City.mmdb

# Threat Intelligence (Optional)
THREAT_INTEL_ENABLED=true
THREAT_INTEL_API_KEY=your-api-key
```

## Testing

### Run All Tests
```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Generate coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Run Specific Test Suites
```bash
# Test authentication
go test ./internal/auth/...

# Test API handlers
go test ./internal/api/...

# Test database repositories
go test ./internal/repository/...
```

## Development

### Project Standards
- **Architecture**: Clean Architecture (Handler → Service → Repository)
- **Error Handling**: Structured error responses with proper HTTP status codes
- **Validation**: Input validation at handler level
- **Security**: JWT middleware for protected endpoints
- **Logging**: Structured logging with context
- **Testing**: Unit tests for business logic, integration tests for endpoints

### Adding New Endpoints

1. Define the handler in `internal/api/`
2. Implement business logic in `internal/service/`
3. Add database operations in `internal/repository/`
4. Register route in `internal/api/router.go`
5. Add tests in corresponding `*_test.go` files

## Deployment

### Production Checklist
- [ ] Set strong `JWT_SECRET` in environment
- [ ] Configure CORS for production domains
- [ ] Enable HTTPS/TLS
- [ ] Set up PostgreSQL (recommended for production)
- [ ] Configure email alerts (SMTP settings)
- [ ] Set up log rotation
- [ ] Enable rate limiting
- [ ] Configure GeoIP database
- [ ] Set up monitoring and alerting

### Systemd Service Example
```ini
[Unit]
Description=WAF API Server
After=network.target

[Service]
Type=simple
User=waf
WorkingDirectory=/opt/waf-api
ExecStart=/opt/waf-api/api-server
Restart=always
Environment="PORT=8081"
Environment="DATABASE_URL=/var/lib/waf/waf.db"

[Install]
WantedBy=multi-user.target
```

## Troubleshooting

### Common Issues

**Database locked error**
- Ensure only one instance is accessing the SQLite database
- Consider switching to PostgreSQL for concurrent access

**JWT token invalid**
- Check that `JWT_SECRET` is consistent across restarts
- Verify token hasn't expired

**CORS errors**
- Add frontend origin to `CORS_ORIGINS` environment variable
- Check that origin includes protocol (http/https)

**Rate limit exceeded**
- Adjust `RATE_LIMIT_REQUESTS` and `RATE_LIMIT_DURATION`
- Check if IP is being extracted correctly through proxies

## Performance Tips

- Use PostgreSQL instead of SQLite for production
- Enable caching for frequently accessed data
- Use database indexes for common query patterns
- Configure connection pooling for database
- Monitor API response times and optimize slow endpoints
- Use pagination for large datasets

## Security Best Practices

- Never commit `.env` file with secrets
- Rotate JWT secrets periodically
- Use strong passwords for database
- Enable HTTPS in production
- Keep dependencies updated
- Implement request logging for audit trails
- Set appropriate rate limits
- Validate all user inputs
- Use prepared statements (already implemented)
- Enable 2FA for admin accounts