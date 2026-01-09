#!/bin/bash

# SSO Auth Server - Quick Start Script
# This script automates the entire setup process

set -e  # Exit on error

echo "================================================"
echo "SSO Authentication Server - Quick Start"
echo "================================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if .env exists
if [ ! -f .env ]; then
    echo -e "${YELLOW}⚠ .env file not found. Creating from example...${NC}"
    if [ -f .env.example ]; then
        cp .env.example .env
    else
        echo -e "${RED}✗ .env.example not found. Please create .env manually.${NC}"
        exit 1
    fi
fi

# Check PHP version
echo "Checking PHP version..."
PHP_VERSION=$(php -r "echo PHP_VERSION;")
echo -e "${GREEN}✓ PHP version: $PHP_VERSION${NC}"

# Check if Composer is installed
if ! command -v composer &> /dev/null; then
    echo -e "${RED}✗ Composer not found. Please install Composer first.${NC}"
    echo "Visit: https://getcomposer.org/download/"
    exit 1
fi

echo -e "${GREEN}✓ Composer found${NC}"

# Install dependencies
echo ""
echo "Installing dependencies..."
if [ "$1" == "--no-dev" ]; then
    composer install --no-dev --optimize-autoloader
else
    composer install
fi

echo -e "${GREEN}✓ Dependencies installed${NC}"

# Create directories
echo ""
echo "Creating directory structure..."
bash create-directories.sh 2>/dev/null || {
    mkdir -p admin/Controllers admin/Middleware admin/Services
    mkdir -p admin/templates/admin/auth admin/templates/admin/users
    mkdir -p config database
    mkdir -p public/admin/css public/admin/js public/uploads/avatars
    mkdir -p src/Controllers src/Helpers src/Middleware src/Models src/Services
    mkdir -p templates cache logs
    chmod -R 755 public
    chmod -R 777 public/uploads cache logs 2>/dev/null || true
}

echo -e "${GREEN}✓ Directory structure created${NC}"

# Check MySQL connection
echo ""
echo "Checking database configuration..."

# Source .env file
export $(cat .env | grep -v '^#' | xargs)

# Test MySQL connection
if php -r "
    try {
        new PDO('mysql:host='.\$_ENV['DB_HOST'], \$_ENV['DB_USER'], \$_ENV['DB_PASS']);
        echo 'OK';
    } catch (Exception \$e) {
        echo 'FAIL';
    }
" | grep -q "OK"; then
    echo -e "${GREEN}✓ MySQL connection successful${NC}"
else
    echo -e "${RED}✗ MySQL connection failed${NC}"
    echo "Please check your database credentials in .env file"
    exit 1
fi

# Setup database
echo ""
echo "Setting up database..."
php setup-database.php

# Generate JWT secret if needed
if grep -q "your-super-secret-jwt-key-change-this" .env; then
    echo ""
    echo "Generating secure JWT secret..."
    JWT_SECRET=$(openssl rand -base64 32 | tr -d '\n')
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        sed -i '' "s|JWT_SECRET=.*|JWT_SECRET=$JWT_SECRET|" .env
    else
        # Linux
        sed -i "s|JWT_SECRET=.*|JWT_SECRET=$JWT_SECRET|" .env
    fi
    echo -e "${GREEN}✓ JWT secret generated${NC}"
fi

# Success message
echo ""
echo "================================================"
echo -e "${GREEN}✓ Setup completed successfully!${NC}"
echo "================================================"
echo ""
echo "Credentials:"
echo "------------"
echo "Admin Login:"
echo "  URL: http://localhost:8079/admin/login"
echo "  Username: superadmin"
echo "  Password: Admin123!"
echo ""
echo "Test User:"
echo "  Email: test@example.com"
echo "  Password: Test123!"
echo ""
echo "To start the server, run:"
echo "  ${GREEN}composer start${NC}"
echo ""
echo "Or manually:"
echo "  ${GREEN}php -S localhost:8079 -t public${NC}"
echo ""
echo "================================================"

# Ask if user wants to start server
read -p "Start the development server now? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    chmod +x start-server.sh
    ./start-server.sh
fi