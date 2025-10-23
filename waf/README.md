# Caddy WAF Module

Web Application Firewall middleware for Caddy server with multi-attack detection capabilities.

## Features

- **XSS Detection**: Cross-Site Scripting prevention
- **SQLi Detection**: SQL Injection protection
- **LFI Detection**: Local File Inclusion blocking
- **RFI Detection**: Remote File Inclusion blocking
- **Command Injection**: Command execution prevention
- **Structured Logging**: JSON-formatted security logs
- **Flexible Configuration**: YAML-based rule management

## Installation

### Using xcaddy
```bash
xcaddy build --with github.com/yourusername/waf-siem-advanced-detection/waf
```

### From source
```bash
cd waf
go build -o caddy cmd/caddy-waf/main.go
```

## Configuration

### Caddyfile Example
```caddy
{
    order waf before file_server
}

:8080 {
    waf {
        rules /etc/caddy/waf-rules.yaml
        log_file /var/log/caddy/waf.log
        block_mode true
    }
    
    root * /var/www/html
    file_server
}
```

### Rules Configuration

See [configs/rules.yaml](configs/rules.yaml) for rule configuration.

## Testing
```bash
# Run tests
go test ./...

# Run with coverage
go test -cover ./...

# Test specific detector
go test ./internal/detector -run TestXSS
```

## Log Format

Logs are written in JSON format:
```json
{
  "timestamp": "2025-10-23T20:00:00Z",
  "threat_type": "XSS",
  "severity": "HIGH",
  "description": "XSS pattern detected",
  "client_ip": "192.168.1.100",
  "method": "GET",
  "url": "/search?q=<script>alert(1)</script>",
  "user_agent": "Mozilla/5.0...",
  "payload": "<script>alert(1)</script>"
}
```

## Development

### Adding New Detectors

1. Create detector in `internal/detector/`
2. Implement `Detect(string) (bool, string)` method
3. Register in `detector.go`
4. Add tests in `*_test.go`

### Project Structure
```
waf/
├── cmd/caddy-waf/      # Main entry point
├── internal/
│   ├── detector/       # Attack detectors
│   └── logger/         # Logging system
├── pkg/waf/            # Public API
├── configs/            # Configuration files
└── tests/              # Integration tests
```

## License

See root LICENSE file.