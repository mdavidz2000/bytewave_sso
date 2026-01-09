<?php
namespace App\Services;

use PDO;
use PDOException;
use Exception;
use App\Services\EmailService;

class UserService
{
    private $pdo;
    private $emailService;

    public function __construct(PDO $pdo, EmailService $emailService = null)
    {
        $this->pdo = $pdo;
        $this->emailService = $emailService;
    }

    // Registration methods
    public function register(array $data): array
    {
        try {
            $this->pdo->beginTransaction();

            // Check if email already exists
            if ($this->getUserByEmail($data['email'])) {
                throw new Exception('Email already registered');
            }

            // Hash password
            $hashedPassword = password_hash($data['password'], PASSWORD_DEFAULT);

            // Insert user
            $stmt = $this->pdo->prepare("
                INSERT INTO users (email, password, name, phone, created_at) 
                VALUES (:email, :password, :name, :phone, NOW())
            ");
            
            $stmt->execute([
                'email' => $data['email'],
                'password' => $hashedPassword,
                'name' => $data['name'],
                'phone' => $data['phone'] ?? null
            ]);

            $userId = $this->pdo->lastInsertId();

            // Create default preferences
            $stmt = $this->pdo->prepare("
                INSERT INTO user_preferences (user_id) VALUES (:user_id)
            ");
            $stmt->execute(['user_id' => $userId]);

            // Assign default role
            $stmt = $this->pdo->prepare("
                INSERT INTO user_roles (user_id, role_id) 
                VALUES (:user_id, (SELECT id FROM roles WHERE name = 'user'))
            ");
            $stmt->execute(['user_id' => $userId]);

            // Generate email verification token
            $verificationToken = $this->generateVerificationToken($userId);

            $this->pdo->commit();

            // Send verification email
            if ($this->emailService) {
                $this->emailService->sendVerificationEmail($data['email'], $verificationToken);
            }

            return $this->getUserById($userId);

        } catch (Exception $e) {
            $this->pdo->rollBack();
            throw $e;
        }
    }

    // Profile management
    public function updateProfile(int $userId, array $data): array
    {
        $allowedFields = ['name', 'phone', 'address', 'city', 'country', 'postal_code', 'date_of_birth'];
        $updateData = array_intersect_key($data, array_flip($allowedFields));
        
        if (empty($updateData)) {
            return $this->getUserById($userId);
        }

        $updateData['updated_at'] = date('Y-m-d H:i:s');
        
        $setClause = implode(', ', array_map(fn($field) => "$field = :$field", array_keys($updateData)));
        
        $stmt = $this->pdo->prepare("
            UPDATE users 
            SET $setClause 
            WHERE id = :id
        ");
        
        $updateData['id'] = $userId;
        $stmt->execute($updateData);

        return $this->getUserById($userId);
    }

    public function updateAvatar(int $userId, string $avatarPath): array
    {
        $stmt = $this->pdo->prepare("
            UPDATE users 
            SET avatar = :avatar 
            WHERE id = :id
        ");
        
        $stmt->execute(['avatar' => $avatarPath, 'id' => $userId]);

        return $this->getUserById($userId);
    }

    public function changePassword(int $userId, string $currentPassword, string $newPassword): bool
    {
        $user = $this->getUserWithPassword($userId);
        
        if (!$user || !password_verify($currentPassword, $user['password'])) {
            throw new Exception('Current password is incorrect');
        }

        $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
        
        $stmt = $this->pdo->prepare("
            UPDATE users 
            SET password = :password 
            WHERE id = :id
        ");
        
        return $stmt->execute([
            'password' => $hashedPassword,
            'id' => $userId
        ]);
    }

    // Password reset
    public function requestPasswordReset(string $email): string
    {
        $user = $this->getUserByEmail($email);
        if (!$user) {
            // Don't reveal that email doesn't exist
            return 'If the email exists, a reset link has been sent.';
        }

        // Generate reset token
        $token = bin2hex(random_bytes(32));
        $expiresAt = date('Y-m-d H:i:s', strtotime('+1 hour'));

        $stmt = $this->pdo->prepare("
            INSERT INTO password_reset_tokens (email, token, expires_at) 
            VALUES (:email, :token, :expires_at)
        ");
        
        $stmt->execute([
            'email' => $email,
            'token' => password_hash($token, PASSWORD_DEFAULT),
            'expires_at' => $expiresAt
        ]);

        // Send reset email
        if ($this->emailService) {
            $this->emailService->sendPasswordResetEmail($email, $token);
        }

        return 'If the email exists, a reset link has been sent.';
    }

    public function resetPassword(string $token, string $newPassword): bool
    {
        // Find valid token
        $stmt = $this->pdo->prepare("
            SELECT * FROM password_reset_tokens 
            WHERE expires_at > NOW() 
            AND used = FALSE
        ");
        
        $stmt->execute();
        $tokens = $stmt->fetchAll();

        foreach ($tokens as $tokenRecord) {
            if (password_verify($token, $tokenRecord['token'])) {
                // Update password
                $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
                
                $stmt = $this->pdo->prepare("
                    UPDATE users 
                    SET password = :password 
                    WHERE email = :email
                ");
                
                $stmt->execute([
                    'password' => $hashedPassword,
                    'email' => $tokenRecord['email']
                ]);

                // Mark token as used
                $stmt = $this->pdo->prepare("
                    UPDATE password_reset_tokens 
                    SET used = TRUE 
                    WHERE id = :id
                ");
                
                $stmt->execute(['id' => $tokenRecord['id']]);

                return true;
            }
        }

        throw new Exception('Invalid or expired reset token');
    }

    // Email verification
    public function generateVerificationToken(int $userId): string
    {
        $token = bin2hex(random_bytes(32));
        $expiresAt = date('Y-m-d H:i:s', strtotime('+24 hours'));

        $stmt = $this->pdo->prepare("
            INSERT INTO email_verification_tokens (user_id, token, expires_at) 
            VALUES (:user_id, :token, :expires_at)
        ");
        
        $stmt->execute([
            'user_id' => $userId,
            'token' => password_hash($token, PASSWORD_DEFAULT),
            'expires_at' => $expiresAt
        ]);

        return $token;
    }

    public function verifyEmail(string $token): bool
    {
        // Find valid token
        $stmt = $this->pdo->prepare("
            SELECT * FROM email_verification_tokens 
            WHERE expires_at > NOW() 
            AND used = FALSE
        ");
        
        $stmt->execute();
        $tokens = $stmt->fetchAll();

        foreach ($tokens as $tokenRecord) {
            if (password_verify($token, $tokenRecord['token'])) {
                // Update user as verified
                $stmt = $this->pdo->prepare("
                    UPDATE users 
                    SET email_verified_at = NOW() 
                    WHERE id = :id
                ");
                
                $stmt->execute(['id' => $tokenRecord['user_id']]);

                // Mark token as used
                $stmt = $this->pdo->prepare("
                    UPDATE email_verification_tokens 
                    SET used = TRUE 
                    WHERE id = :id
                ");
                
                $stmt->execute(['id' => $tokenRecord['id']]);

                return true;
            }
        }

        throw new Exception('Invalid or expired verification token');
    }

    // Account settings
    public function updatePreferences(int $userId, array $preferences): array
    {
        $allowedFields = [
            'notifications_email', 'notifications_push',
            'privacy_profile_public', 'privacy_email_public',
            'theme', 'preferred_language', 'timezone'
        ];
        
        $updateData = array_intersect_key($preferences, array_flip($allowedFields));
        
        if (empty($updateData)) {
            return $this->getPreferences($userId);
        }

        // Check if preferences exist
        $existing = $this->getPreferences($userId);
        
        if ($existing) {
            $setClause = implode(', ', array_map(fn($field) => "$field = :$field", array_keys($updateData)));
            
            $stmt = $this->pdo->prepare("
                UPDATE user_preferences 
                SET $setClause 
                WHERE user_id = :user_id
            ");
            
            $updateData['user_id'] = $userId;
            $stmt->execute($updateData);
        } else {
            $stmt = $this->pdo->prepare("
                INSERT INTO user_preferences (user_id, " . 
                implode(', ', array_keys($updateData)) . ") 
                VALUES (:" . implode(', :', array_keys($updateData)) . ")
            ");
            
            $updateData['user_id'] = $userId;
            $stmt->execute($updateData);
        }

        return $this->getPreferences($userId);
    }

    public function getPreferences(int $userId): array
    {
        $stmt = $this->pdo->prepare("
            SELECT * FROM user_preferences 
            WHERE user_id = :user_id
        ");
        
        $stmt->execute(['user_id' => $userId]);
        return $stmt->fetch(PDO::FETCH_ASSOC) ?: [];
    }

    // Two-factor authentication
    public function enableTwoFactor(int $userId, string $secret): bool
    {
        $stmt = $this->pdo->prepare("
            UPDATE users 
            SET two_factor_enabled = TRUE, two_factor_secret = :secret 
            WHERE id = :id
        ");
        
        return $stmt->execute([
            'secret' => $secret,
            'id' => $userId
        ]);
    }

    public function disableTwoFactor(int $userId): bool
    {
        $stmt = $this->pdo->prepare("
            UPDATE users 
            SET two_factor_enabled = FALSE, two_factor_secret = NULL 
            WHERE id = :id
        ");
        
        return $stmt->execute(['id' => $userId]);
    }

    // Session management
    public function logSession(int $userId, array $sessionData): void
    {
        $stmt = $this->pdo->prepare("
            INSERT INTO user_sessions 
            (user_id, session_id, access_token_hash, refresh_token_hash, 
             ip_address, user_agent, expires_at) 
            VALUES (:user_id, :session_id, :access_token_hash, :refresh_token_hash,
                    :ip_address, :user_agent, :expires_at)
        ");
        
        $stmt->execute([
            'user_id' => $userId,
            'session_id' => $sessionData['session_id'],
            'access_token_hash' => $sessionData['access_token_hash'] ?? null,
            'refresh_token_hash' => $sessionData['refresh_token_hash'] ?? null,
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? null,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
            'expires_at' => date('Y-m-d H:i:s', strtotime('+30 days'))
        ]);
    }

    public function logoutAllSessions(int $userId): void
    {
        $stmt = $this->pdo->prepare("
            DELETE FROM user_sessions 
            WHERE user_id = :user_id
        ");
        
        $stmt->execute(['user_id' => $userId]);
    }

    public function getActiveSessions(int $userId): array
    {
        $stmt = $this->pdo->prepare("
            SELECT * FROM user_sessions 
            WHERE user_id = :user_id 
            AND expires_at > NOW() 
            ORDER BY last_activity DESC
        ");
        
        $stmt->execute(['user_id' => $userId]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    // API keys management
    public function createApiKey(int $userId, string $name, array $scopes = []): array
    {
        $apiKey = bin2hex(random_bytes(32));
        $secret = bin2hex(random_bytes(32));
        $secretHash = password_hash($secret, PASSWORD_DEFAULT);

        $stmt = $this->pdo->prepare("
            INSERT INTO api_keys 
            (user_id, name, api_key, secret_hash, scopes, expires_at) 
            VALUES (:user_id, :name, :api_key, :secret_hash, :scopes, DATE_ADD(NOW(), INTERVAL 1 YEAR))
        ");
        
        $stmt->execute([
            'user_id' => $userId,
            'name' => $name,
            'api_key' => $apiKey,
            'secret_hash' => $secretHash,
            'scopes' => json_encode($scopes)
        ]);

        return [
            'api_key' => $apiKey,
            'secret' => $secret, // Only shown once
            'id' => $this->pdo->lastInsertId()
        ];
    }

    public function revokeApiKey(int $userId, int $apiKeyId): bool
    {
        $stmt = $this->pdo->prepare("
            UPDATE api_keys 
            SET is_active = FALSE 
            WHERE id = :id AND user_id = :user_id
        ");
        
        return $stmt->execute([
            'id' => $apiKeyId,
            'user_id' => $userId
        ]);
    }

    public function getApiKeys(int $userId): array
    {
        $stmt = $this->pdo->prepare("
            SELECT id, name, api_key, scopes, last_used_at, expires_at, is_active, created_at 
            FROM api_keys 
            WHERE user_id = :user_id 
            ORDER BY created_at DESC
        ");
        
        $stmt->execute(['user_id' => $userId]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    // Helper methods
    private function getUserWithPassword(int $userId): ?array
    {
        $stmt = $this->pdo->prepare("
            SELECT * FROM users 
            WHERE id = :id
        ");
        
        $stmt->execute(['id' => $userId]);
        return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
    }

    public function getUserById(int $id): ?array
    {
        $stmt = $this->pdo->prepare("
            SELECT id, email, name, avatar, phone, address, city, country, 
                   postal_code, date_of_birth, is_active, email_verified_at,
                   two_factor_enabled, preferred_language, timezone, created_at
            FROM users 
            WHERE id = :id
        ");
        
        $stmt->execute(['id' => $id]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            $user['roles'] = $this->getUserRoles($id);
            $user['permissions'] = $this->getUserPermissions($id);
        }

        return $user ?: null;
    }

    public function getUserByEmail(string $email): ?array
    {
        $stmt = $this->pdo->prepare("
            SELECT id, email, name, avatar, phone, is_active, email_verified_at,
                   two_factor_enabled, password
            FROM users 
            WHERE email = :email
        ");
        
        $stmt->execute(['email' => $email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            unset($user['password']); // Don't return password
        }

        return $user ?: null;
    }

    public function authenticate(string $email, string $password): ?array
    {
        $stmt = $this->pdo->prepare("
            SELECT * FROM users 
            WHERE email = :email AND is_active = TRUE
        ");
        
        $stmt->execute(['email' => $email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password'])) {
            unset($user['password']);
            $user['roles'] = $this->getUserRoles($user['id']);
            $user['permissions'] = $this->getUserPermissions($user['id']);
            return $user;
        }

        return null;
    }

    private function getUserRoles(int $userId): array
    {
        $stmt = $this->pdo->prepare("
            SELECT r.name 
            FROM roles r 
            JOIN user_roles ur ON r.id = ur.role_id 
            WHERE ur.user_id = :user_id
        ");
        
        $stmt->execute(['user_id' => $userId]);
        return $stmt->fetchAll(PDO::FETCH_COLUMN);
    }

    private function getUserPermissions(int $userId): array
    {
        // You can extend this with a permissions table
        $roles = $this->getUserRoles($userId);
        
        $permissions = [];
        foreach ($roles as $role) {
            $permissions = array_merge($permissions, $this->getRolePermissions($role));
        }
        
        return array_unique($permissions);
    }

    private function getRolePermissions(string $role): array
    {
        // Define role-based permissions
        $permissions = [
            'user' => ['profile.view', 'profile.edit', 'api_keys.manage'],
            'admin' => ['users.manage', 'system.config']
        ];

        return $permissions[$role] ?? [];
    }

    public function searchUsers(array $filters, int $page = 1, int $perPage = 20): array
    {
        $where = ['1=1'];
        $params = [];
        
        if (!empty($filters['search'])) {
            $where[] = '(name LIKE :search OR email LIKE :search)';
            $params['search'] = '%' . $filters['search'] . '%';
        }
        
        if (!empty($filters['role'])) {
            $where[] = 'EXISTS (
                SELECT 1 FROM user_roles ur 
                JOIN roles r ON ur.role_id = r.id 
                WHERE ur.user_id = u.id AND r.name = :role
            )';
            $params['role'] = $filters['role'];
        }
        
        $whereClause = implode(' AND ', $where);
        $offset = ($page - 1) * $perPage;
        
        // Get total count
        $stmt = $this->pdo->prepare("
            SELECT COUNT(*) as total 
            FROM users u 
            WHERE $whereClause
        ");
        
        $stmt->execute($params);
        $total = $stmt->fetch(PDO::FETCH_ASSOC)['total'];
        
        // Get users
        $stmt = $this->pdo->prepare("
            SELECT id, email, name, avatar, is_active, email_verified_at, created_at 
            FROM users u 
            WHERE $whereClause 
            ORDER BY created_at DESC 
            LIMIT :limit OFFSET :offset
        ");
        
        $params['limit'] = $perPage;
        $params['offset'] = $offset;
        
        $stmt->execute($params);
        $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        return [
            'users' => $users,
            'total' => $total,
            'page' => $page,
            'per_page' => $perPage,
            'total_pages' => ceil($total / $perPage)
        ];
    }

    public function deactivateAccount(int $userId): bool
    {
        $stmt = $this->pdo->prepare("
            UPDATE users 
            SET is_active = FALSE 
            WHERE id = :id
        ");
        
        return $stmt->execute(['id' => $userId]);
    }

    public function deleteAccount(int $userId): bool
    {
        $stmt = $this->pdo->prepare("DELETE FROM users WHERE id = :id");
        return $stmt->execute(['id' => $userId]);
    }
}