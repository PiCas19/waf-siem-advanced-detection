#!/bin/bash
set -e

echo "Installing WAF-SIEM..."

# Install WAF
sudo cp waf/caddy /usr/local/bin/caddy-waf
sudo chmod +x /usr/local/bin/caddy-waf

# Install API
sudo cp api/waf-api /usr/local/bin/
sudo chmod +x /usr/local/bin/waf-api

# Install systemd services
sudo cp deployment/systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload

# Enable services
sudo systemctl enable caddy-waf waf-api

echo "Installation complete!"
echo "Start services with: sudo systemctl start caddy-waf waf-api"