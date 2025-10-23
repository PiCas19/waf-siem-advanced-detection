#!/bin/bash
set -e

echo "Building WAF-SIEM Project..."

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Build WAF
echo -e "${YELLOW}Building WAF module...${NC}"
cd waf
xcaddy build --with github.com/PiCas19/waf-siem-advanced-detection/waf
cd ..
echo -e "${GREEN} WAF built successfully${NC}"

# Build Dashboard
echo -e "${YELLOW}Building Dashboard...${NC}"
cd dashboard
npm install
npm run build
cd ..
echo -e "${GREEN} Dashboard built successfully${NC}"

# Build API
echo -e "${YELLOW}Building API...${NC}"
cd api
go build -o waf-api cmd/api-server/main.go
cd ..
echo -e "${GREEN} API built successfully${NC}"

echo -e "${GREEN} Build complete!${NC}"