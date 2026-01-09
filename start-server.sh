#!/bin/bash

# SSO Auth Server Startup Script

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "================================================"
echo "SSO Authentication Server"
echo "================================================"
echo ""

# Check if vendor directory exists
if [ ! -d "vendor" ]; then
    echo -e "${YELLOW}⚠ Dependencies not installed. Running composer install...${NC}"
    composer install
fi

# Check if .env exists
if [ ! -f ".env" ]; then
    echo -e "${YELLOW}⚠ .env file not found. Please copy .env.example to .env and configure it.${NC}"
    exit 1
fi

# Create necessary directories
mkdir -p public/uploads/avatars cache logs
chmod -R 777 public/uploads cache logs 2>/dev/null || true

# Check if database is set up
export $(cat .env | grep -v '^#' | xargs)

php -r "
try {
    \$pdo = new PDO('mysql:host='.\$_ENV['DB_HOST'].';dbname='.\$_ENV['DB_NAME'], \$_ENV['DB_USER'], \$_ENV['DB_PASS']);
    \$result = \$pdo->query('SELECT COUNT(*) FROM users');
    echo 'OK';
} catch (Exception \$e) {
    echo 'FAIL';
}
" > /tmp/db_check.txt 2>&1

if grep -q "FAIL" /tmp/db_check.txt; then
    echo -e "${YELLOW}⚠ Database not set up. Running setup script...${NC}"
    php setup-database.php
fi

rm -f /tmp/db_check.txt

# Start the server
echo ""
echo -e "${GREEN}✓ Starting development server...${NC}"
echo ""
echo "Server URLs:"
echo "  Home:          http://localhost:8079/"
echo "  Admin Login:   http://localhost:8079/admin/login"
echo ""
echo "Credentials:"
echo "  Admin:         superadmin / Admin123!"
echo "  Test User:     test@example.com / Test123!"
echo ""
echo "================================================"
echo "Press Ctrl+C to stop the server"
echo "================================================"
echo ""

# Start with router.php for proper routing
php -S localhost:8079 -t public router.php