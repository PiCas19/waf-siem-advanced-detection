# WAF API Backend

RESTful API backend for WAF dashboard with JWT authentication and database management.

## Features

- JWT-based authentication
- User registration and login
- Rules CRUD operations
- Log management
- IP blocklist management
- WebSocket support for real-time alerts

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

### Protected Endpoints (require JWT)

- `GET /api/stats` - Dashboard statistics
- `GET /api/rules` - List WAF rules
- `POST /api/rules` - Create new rule
- `PUT /api/rules/:id` - Update rule
- `DELETE /api/rules/:id` - Delete rule
- `GET /api/logs` - Get security logs
- `GET /api/blocklist` - Get blocked IPs
- `POST /api/blocklist` - Block IP address

### Admin Endpoints

- `GET /api/admin/users` - List all users

## Database

Default: SQLite (`waf.db`)

### Models

- **User**: Dashboard users
- **Rule**: WAF detection rules
- **Log**: Security event logs
- **BlockedIP**: IP blocklist

## Environment Variables
```bash
DATABASE_URL=waf.db
JWT_SECRET=your-secret-key
PORT=8081
```

## Testing
```bash
go test ./...
```