<?php
namespace App\Admin\Services;

use PDO;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Exception;

class AdminAuthService
{
    private $pdo;
    private $jwtSecret;
    private $jwtAlgorithm = 'HS256';

    public function __construct(PDO $pdo, string $jwtSecret)
    {
        $this->pdo = $pdo;
        $this->jwtSecret = $jwtSecret;
    }

    public function authenticate(string $username, string $password): ?array
    {
        $stmt = $this->pdo->prepare("
            SELECT * FROM admin_users 
            WHERE (username = :username OR email = :username) 
            AND is_active = TRUE
            AND (locked_until IS NULL OR locked_until < NOW())
        ");
        
        $stmt->execute(['username' => $username]);
        $admin = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$admin || !password_verify($password, $admin['password'])) {
            $this->recordFailedLogin($username);
            return null;
        }

        // Reset failed login attempts
        $this->resetFailedLogins($admin['id']);

        // Update last login
        $stmt = $this->pdo->prepare("
            UPDATE admin_users 
            SET last_login_at = NOW(), last_login_ip = :ip 
            WHERE id = :id
        ");
        
        $stmt->execute([
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'id' => $admin['id']
        ]);

        // Get admin permissions
        $permissions = $this->getAdminPermissions($admin['id']);
        
        // Generate JWT token
        $token = $this->generateToken($admin, $permissions);

        unset($admin['password']);

        return [
            'admin' => $admin,
            'token' => $token,
            'permissions' => $permissions
        ];
    }

    public function generateToken(array $admin, array $permissions): string
    {
        $payload = [
            'iss' => 'sso-admin',
            'aud' => 'admin-dashboard',
            'iat' => time(),
            'exp' => time() + (8 * 3600), // 8 hours
            'sub' => $admin['id'],
            'username' => $admin['username'],
            'email' => $admin['email'],
            'name' => $admin['name'],
            'is_super_admin' => (bool)$admin['is_super_admin'],
            'permissions' => $permissions,
            'type' => 'admin_token'
        ];

        return JWT::encode($payload, $this->jwtSecret, $this->jwtAlgorithm);
    }

    public function validateToken(string $token): array
    {
        try {
            $decoded = JWT::decode($token, new Key($this->jwtSecret, $this->jwtAlgorithm));
            
            if ($decoded->type !== 'admin_token') {
                throw new Exception('Invalid token type');
            }

            return (array)$decoded;
        } catch (Exception $e) {
            throw new Exception('Invalid admin token: ' . $e->getMessage());
        }
    }

    private function getAdminPermissions(int $adminId): array
    {
        $stmt = $this->pdo->prepare("
            SELECT p.code 
            FROM admin_permissions p
            JOIN admin_role_permissions rp ON p.id = rp.permission_id
            JOIN admin_user_roles ur ON rp.role_id = ur.role_id
            WHERE ur.admin_user_id = :admin_id
            UNION
            SELECT p.code 
            FROM admin_permissions p
            JOIN admin_user_permissions up ON p.id = up.permission_id
            WHERE up.admin_user_id = :admin_id
        ");
        
        $stmt->execute(['admin_id' => $adminId]);
        return $stmt->fetchAll(PDO::FETCH_COLUMN);
    }

    private function recordFailedLogin(string $identifier): void
    {
        $stmt = $this->pdo->prepare("
            UPDATE admin_users 
            SET failed_login_attempts = failed_login_attempts + 1,
                locked_until = CASE 
                    WHEN failed_login_attempts >= 4 THEN DATE_ADD(NOW(), INTERVAL 15 MINUTE)
                    ELSE locked_until 
                END
            WHERE (username = :identifier OR email = :identifier)
        ");
        
        $stmt->execute(['identifier' => $identifier]);
    }

    private function resetFailedLogins(int $adminId): void
    {
        $stmt = $this->pdo->prepare("
            UPDATE admin_users 
            SET failed_login_attempts = 0, locked_until = NULL 
            WHERE id = :id
        ");
        
        $stmt->execute(['id' => $adminId]);
    }

    public function hasPermission(array $adminData, string $permission): bool
    {
        if ($adminData['is_super_admin'] ?? false) {
            return true;
        }

        $permissions = $adminData['permissions'] ?? [];
        return in_array($permission, $permissions);
    }
}