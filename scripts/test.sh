#!/bin/bash
set -e

echo "Running Tests..."

# Test WAF
echo "Testing WAF..."
cd waf
go test ./... -v
cd ..

# Test API
echo "Testing API..."
cd api
go test ./... -v
cd ..

echo "All tests passed!"