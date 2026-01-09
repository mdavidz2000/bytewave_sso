<?php
/**
 * Database Setup Script
 * Run this script to create all necessary database tables
 * 
 * Usage: php setup-database.php
 */

require __DIR__ . '/vendor/autoload.php';

// Load environment variables
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

try {
    // Connect to MySQL server (without database)
    $pdo = new PDO(
        "mysql:host={$_ENV['DB_HOST']};charset=utf8mb4",
        $_ENV['DB_USER'],
        $_ENV['DB_PASS'],
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
    );

    echo "✓ Connected to MySQL server\n";

    // Create database if not exists
    $dbName = $_ENV['DB_NAME'];
    $pdo->exec("CREATE DATABASE IF NOT EXISTS `$dbName` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
    echo "✓ Database '$dbName' created/verified\n";

    // Use the database
    $pdo->exec("USE `$dbName`");

    // Read and execute schema files
    $schemaFiles = [
        'database/schema_001.sql',
        'database/admin_schema_001.sql'
    ];

    foreach ($schemaFiles as $file) {
        if (!file_exists($file)) {
            echo "✗ Schema file not found: $file\n";
            continue;
        }

        echo "\nExecuting: $file\n";
        $sql = file_get_contents($file);
        
        // Split by semicolons but keep them for execution
        $statements = array_filter(
            array_map('trim', explode(';', $sql)),
            function($stmt) {
                return !empty($stmt) && strpos($stmt, '--') !== 0;
            }
        );

        foreach ($statements as $statement) {
            if (empty(trim($statement))) continue;
            
            try {
                $pdo->exec($statement);
                echo ".";
            } catch (PDOException $e) {
                // Ignore table already exists errors
                if (strpos($e->getMessage(), 'already exists') === false) {
                    echo "\n⚠ Warning: " . $e->getMessage() . "\n";
                }
            }
        }
        echo "\n✓ Completed: $file\n";
    }

    // Create default super admin user
    echo "\n--- Creating Default Admin User ---\n";
    
    $hashedPassword = password_hash('Admin123!', PASSWORD_DEFAULT);
    
    $stmt = $pdo->prepare("
        INSERT INTO admin_users (username, email, password, name, is_super_admin) 
        VALUES ('superadmin', 'admin@example.com', ?, 'Super Admin', TRUE)
        ON DUPLICATE KEY UPDATE password = ?
    ");
    
    $stmt->execute([$hashedPassword, $hashedPassword]);
    
    echo "✓ Super admin created\n";
    echo "  Username: superadmin\n";
    echo "  Password: Admin123!\n";
    echo "  Email: admin@example.com\n";

    // Assign super admin role
    $pdo->exec("
        INSERT IGNORE INTO admin_user_roles (admin_user_id, role_id)
        SELECT 
            (SELECT id FROM admin_users WHERE username = 'superadmin' LIMIT 1),
            (SELECT id FROM admin_roles WHERE name = 'Super Admin' LIMIT 1)
    ");

    // Create rate_limits table if not exists
    echo "\n--- Creating Additional Tables ---\n";
    
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS rate_limits (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip_address VARCHAR(45) NOT NULL,
            path VARCHAR(255) NOT NULL,
            timestamp INT NOT NULL,
            INDEX idx_ip_path_time (ip_address, path, timestamp)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    ");
    echo "✓ Rate limits table created\n";

    // Create test user
    echo "\n--- Creating Test User ---\n";
    
    $testPassword = password_hash('Test123!', PASSWORD_DEFAULT);
    
    $stmt = $pdo->prepare("
        INSERT INTO users (email, password, name, is_active, email_verified_at) 
        VALUES ('test@example.com', ?, 'Test User', TRUE, NOW())
        ON DUPLICATE KEY UPDATE password = ?
    ");
    
    $stmt->execute([$testPassword, $testPassword]);
    
    $userId = $pdo->lastInsertId() ?: $pdo->query("SELECT id FROM users WHERE email = 'test@example.com'")->fetchColumn();
    
    // Assign user role
    $pdo->exec("
        INSERT IGNORE INTO user_roles (user_id, role_id)
        SELECT 
            $userId,
            (SELECT id FROM roles WHERE name = 'user' LIMIT 1)
    ");
    
    // Create user preferences
    $pdo->exec("
        INSERT IGNORE INTO user_preferences (user_id) VALUES ($userId)
    ");
    
    echo "✓ Test user created\n";
    echo "  Email: test@example.com\n";
    echo "  Password: Test123!\n";

    echo "\n" . str_repeat("=", 50) . "\n";
    echo "✓ Database setup completed successfully!\n";
    echo str_repeat("=", 50) . "\n\n";

    echo "Next steps:\n";
    echo "1. Start the server: composer start\n";
    echo "2. Visit: http://localhost:8079/admin/login\n";
    echo "3. Login with: superadmin / Admin123!\n\n";

} catch (PDOException $e) {
    echo "✗ Database error: " . $e->getMessage() . "\n";
    exit(1);
} catch (Exception $e) {
    echo "✗ Error: " . $e->getMessage() . "\n";
    exit(1);
}