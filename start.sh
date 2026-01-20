#!/bin/bash

# Threat Radar Startup Script
# This script helps you start Threat Radar quickly and handles common setup tasks

set -e  # Exit on error

echo "
╔════════════════════════════════════════════╗
║     Threat Radar - Startup Script          ║
║     Educational Threat Intelligence        ║
╚════════════════════════════════════════════╝
"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker is not installed${NC}"
    echo "Please install Docker from: https://docs.docker.com/get-docker/"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}❌ Docker Compose is not installed${NC}"
    echo "Please install Docker Compose from: https://docs.docker.com/compose/install/"
    exit 1
fi

echo -e "${GREEN}✓ Docker found${NC}"

# Check if .env exists, create from example if not
if [ ! -f "config/.env" ]; then
    echo -e "${YELLOW}⚠ No .env file found, creating from example...${NC}"
    cp config/.env.example config/.env
    echo -e "${GREEN}✓ Created config/.env${NC}"
    echo -e "${BLUE}💡 You can add API keys to config/.env for real threat data${NC}"
fi

# Show current mode
if grep -q "ALIENVAULT_OTX_API_KEY=.*[a-zA-Z0-9]" config/.env && \
   [ $(grep "ALIENVAULT_OTX_API_KEY=" config/.env | cut -d'=' -f2 | wc -c) -gt 1 ]; then
    echo -e "${GREEN}✓ Running with REAL threat intelligence feeds${NC}"
else
    echo -e "${YELLOW}⚠ Running with EDUCATIONAL MOCK DATA${NC}"
    echo -e "${BLUE}💡 Add API keys to config/.env for real data${NC}"
fi

echo ""
echo "Starting Threat Radar..."
echo ""

# Build and start containers
docker-compose up -d --build

echo ""
echo -e "${GREEN}✓ Containers started successfully!${NC}"
echo ""
echo "Waiting for services to be ready..."

# Wait for backend to be healthy
max_attempts=30
attempt=0
while [ $attempt -lt $max_attempts ]; do
    if curl -s http://localhost:8001/health > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Backend is ready!${NC}"
        break
    fi
    echo -n "."
    sleep 2
    attempt=$((attempt + 1))
done

if [ $attempt -eq $max_attempts ]; then
    echo -e "${RED}❌ Backend failed to start${NC}"
    echo "Check logs with: docker-compose logs backend"
    exit 1
fi

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   🎉 Threat Radar is now running!          ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}📊 Dashboard:${NC}      http://localhost:5173"
echo -e "${BLUE}📖 API Docs:${NC}       http://localhost:8000/docs"
echo -e "${BLUE}🔧 API Endpoint:${NC}   http://localhost:8000"
echo ""
echo -e "${YELLOW}Useful commands:${NC}"
echo "  View logs:     docker-compose logs -f"
echo "  Stop:          docker-compose down"
echo "  Restart:       docker-compose restart"
echo "  View status:   docker-compose ps"
echo ""
echo -e "${GREEN}Happy threat hunting! 🔍${NC}"
