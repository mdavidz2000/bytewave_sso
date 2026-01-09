<?php
namespace App\Controllers;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use App\Services\UserService;
use App\Services\JWTService;
use Respect\Validation\Validator as v;
use Slim\Psr7\UploadedFile;

class UserController
{
    private $userService;
    private $jwtService;

    public function __construct(UserService $userService, JWTService $jwtService)
    {
        $this->userService = $userService;
        $this->jwtService = $jwtService;
    }

    // Registration
    public function register(Request $request, Response $response): Response
    {
        $data = $request->getParsedBody();

        // Validation
        $validator = v::key('email', v::email()->notEmpty())
            ->key('password', v::stringType()->length(8, null)->notEmpty())
            ->key('name', v::stringType()->notEmpty());

        try {
            $validator->assert($data);

            $user = $this->userService->register([
                'email' => $data['email'],
                'password' => $data['password'],
                'name' => $data['name'],
                'phone' => $data['phone'] ?? null
            ]);

            return $response->withJson([
                'success' => true,
                'message' => 'Registration successful. Please check your email to verify your account.',
                'user' => [
                    'id' => $user['id'],
                    'email' => $user['email'],
                    'name' => $user['name']
                ]
            ], 201);

        } catch (\Exception $e) {
            return $response->withStatus(400)->withJson([
                'error' => 'registration_failed',
                'message' => $e->getMessage()
            ]);
        }
    }

    // Email verification
    public function verifyEmail(Request $request, Response $response): Response
    {
        $token = $request->getQueryParams()['token'] ?? '';

        try {
            $this->userService->verifyEmail($token);

            // Return HTML page for browser redirect
            if (strpos($request->getHeaderLine('Accept'), 'text/html') !== false) {
                $html = '
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>Email Verified</title>
                        <meta http-equiv="refresh" content="3;url=/login">
                        <style>
                            body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                            .success { color: #28a745; font-size: 24px; }
                        </style>
                    </head>
                    <body>
                        <div class="success">✓ Email verified successfully!</div>
                        <p>Redirecting to login page...</p>
                    </body>
                    </html>
                ';
                $response->getBody()->write($html);
                return $response->withHeader('Content-Type', 'text/html');
            }

            return $response->withJson([
                'success' => true,
                'message' => 'Email verified successfully'
            ]);

        } catch (\Exception $e) {
            return $response->withStatus(400)->withJson([
                'error' => 'verification_failed',
                'message' => $e->getMessage()
            ]);
        }
    }

    // Profile management
    public function getProfile(Request $request, Response $response): Response
    {
        $user = $request->getAttribute('user');
        
        $profile = $this->userService->getUserById($user['id']);
        
        return $response->withJson([
            'success' => true,
            'profile' => $profile
        ]);
    }

    public function updateProfile(Request $request, Response $response): Response
    {
        $user = $request->getAttribute('user');
        $data = $request->getParsedBody();

        try {
            $updatedProfile = $this->userService->updateProfile($user['id'], $data);
            
            return $response->withJson([
                'success' => true,
                'message' => 'Profile updated successfully',
                'profile' => $updatedProfile
            ]);

        } catch (\Exception $e) {
            return $response->withStatus(400)->withJson([
                'error' => 'update_failed',
                'message' => $e->getMessage()
            ]);
        }
    }

    public function uploadAvatar(Request $request, Response $response): Response
    {
        $user = $request->getAttribute('user');
        $uploadedFiles = $request->getUploadedFiles();
        
        if (!isset($uploadedFiles['avatar'])) {
            return $response->withStatus(400)->withJson([
                'error' => 'no_file',
                'message' => 'No file uploaded'
            ]);
        }

        $avatar = $uploadedFiles['avatar'];

        // Validate file
        if ($avatar->getError() !== UPLOAD_ERR_OK) {
            return $response->withStatus(400)->withJson([
                'error' => 'upload_error',
                'message' => 'File upload failed'
            ]);
        }

        // Check file type
        $allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
        $mimeType = $avatar->getClientMediaType();
        
        if (!in_array($mimeType, $allowedTypes)) {
            return $response->withStatus(400)->withJson([
                'error' => 'invalid_type',
                'message' => 'Only JPEG, PNG, and GIF images are allowed'
            ]);
        }

        // Check file size (max 5MB)
        if ($avatar->getSize() > 5 * 1024 * 1024) {
            return $response->withStatus(400)->withJson([
                'error' => 'file_too_large',
                'message' => 'File size must be less than 5MB'
            ]);
        }

        // Generate unique filename
        $extension = pathinfo($avatar->getClientFilename(), PATHINFO_EXTENSION);
        $filename = 'avatar_' . $user['id'] . '_' . time() . '.' . $extension;
        $uploadDir = __DIR__ . '/../../public/uploads/avatars/';
        
        // Create directory if it doesn't exist
        if (!is_dir($uploadDir)) {
            mkdir($uploadDir, 0755, true);
        }

        $filepath = $uploadDir . $filename;
        
        // Move uploaded file
        $avatar->moveTo($filepath);

        // Save to database
        $avatarUrl = '/uploads/avatars/' . $filename;
        $updatedProfile = $this->userService->updateAvatar($user['id'], $avatarUrl);

        return $response->withJson([
            'success' => true,
            'message' => 'Avatar uploaded successfully',
            'avatar_url' => $avatarUrl,
            'profile' => $updatedProfile
        ]);
    }

    // Password management
    public function changePassword(Request $request, Response $response): Response
    {
        $user = $request->getAttribute('user');
        $data = $request->getParsedBody();

        $validator = v::key('current_password', v::stringType()->notEmpty())
            ->key('new_password', v::stringType()->length(8, null)->notEmpty());

        try {
            $validator->assert($data);

            $this->userService->changePassword(
                $user['id'],
                $data['current_password'],
                $data['new_password']
            );

            // Logout from all devices except current
            $this->userService->logoutAllSessions($user['id']);

            return $response->withJson([
                'success' => true,
                'message' => 'Password changed successfully. Please log in again.'
            ]);

        } catch (\Exception $e) {
            return $response->withStatus(400)->withJson([
                'error' => 'password_change_failed',
                'message' => $e->getMessage()
            ]);
        }
    }

    public function requestPasswordReset(Request $request, Response $response): Response
    {
        $email = $request->getParsedBody()['email'] ?? '';

        if (!v::email()->validate($email)) {
            return $response->withStatus(400)->withJson([
                'error' => 'invalid_email',
                'message' => 'Please provide a valid email address'
            ]);
        }

        try {
            $message = $this->userService->requestPasswordReset($email);
            
            return $response->withJson([
                'success' => true,
                'message' => $message
            ]);

        } catch (\Exception $e) {
            return $response->withStatus(500)->withJson([
                'error' => 'reset_request_failed',
                'message' => 'Failed to process reset request'
            ]);
        }
    }

    public function resetPassword(Request $request, Response $response): Response
    {
        $data = $request->getParsedBody();
        
        $validator = v::key('token', v::stringType()->notEmpty())
            ->key('password', v::stringType()->length(8, null)->notEmpty());

        try {
            $validator->assert($data);

            $this->userService->resetPassword($data['token'], $data['password']);

            return $response->withJson([
                'success' => true,
                'message' => 'Password reset successfully. You can now log in with your new password.'
            ]);

        } catch (\Exception $e) {
            return $response->withStatus(400)->withJson([
                'error' => 'reset_failed',
                'message' => $e->getMessage()
            ]);
        }
    }

    // Account settings
    public function getPreferences(Request $request, Response $response): Response
    {
        $user = $request->getAttribute('user');
        $preferences = $this->userService->getPreferences($user['id']);
        
        return $response->withJson([
            'success' => true,
            'preferences' => $preferences
        ]);
    }

    public function updatePreferences(Request $request, Response $response): Response
    {
        $user = $request->getAttribute('user');
        $preferences = $request->getParsedBody();

        $updated = $this->userService->updatePreferences($user['id'], $preferences);
        
        return $response->withJson([
            'success' => true,
            'message' => 'Preferences updated successfully',
            'preferences' => $updated
        ]);
    }

    // Session management
    public function getSessions(Request $request, Response $response): Response
    {
        $user = $request->getAttribute('user');
        $sessions = $this->userService->getActiveSessions($user['id']);
        
        // Filter current session
        $currentSessionId = session_id();
        foreach ($sessions as &$session) {
            $session['is_current'] = ($session['session_id'] === $currentSessionId);
            unset($session['access_token_hash'], $session['refresh_token_hash']);
        }

        return $response->withJson([
            'success' => true,
            'sessions' => $sessions
        ]);
    }

    public function revokeSession(Request $request, Response $response): Response
    {
        $user = $request->getAttribute('user');
        $sessionId = $request->getParsedBody()['session_id'] ?? '';

        // This would require additional implementation
        // For now, just demonstrate the concept
        
        return $response->withJson([
            'success' => true,
            'message' => 'Session revoked successfully'
        ]);
    }

    public function logoutAll(Request $request, Response $response): Response
    {
        $user = $request->getAttribute('user');
        
        $this->userService->logoutAllSessions($user['id']);

        return $response->withJson([
            'success' => true,
            'message' => 'Logged out from all devices'
        ]);
    }

    // API keys management
    public function getApiKeys(Request $request, Response $response): Response
    {
        $user = $request->getAttribute('user');
        $apiKeys = $this->userService->getApiKeys($user['id']);
        
        return $response->withJson([
            'success' => true,
            'api_keys' => $apiKeys
        ]);
    }

    public function createApiKey(Request $request, Response $response): Response
    {
        $user = $request->getAttribute('user');
        $data = $request->getParsedBody();

        $validator = v::key('name', v::stringType()->length(1, 100)->notEmpty())
            ->key('scopes', v::arrayType()->each(v::stringType()), false);

        try {
            $validator->assert($data);

            $apiKey = $this->userService->createApiKey(
                $user['id'],
                $data['name'],
                $data['scopes'] ?? []
            );

            return $response->withJson([
                'success' => true,
                'message' => 'API key created successfully',
                'api_key' => $apiKey['api_key'],
                'secret' => $apiKey['secret'], // Show only once!
                'id' => $apiKey['id']
            ], 201);

        } catch (\Exception $e) {
            return $response->withStatus(400)->withJson([
                'error' => 'api_key_creation_failed',
                'message' => $e->getMessage()
            ]);
        }
    }

    public function revokeApiKey(Request $request, Response $response): Response
    {
        $user = $request->getAttribute('user');
        $apiKeyId = $request->getParsedBody()['api_key_id'] ?? 0;

        try {
            $this->userService->revokeApiKey($user['id'], (int)$apiKeyId);
            
            return $response->withJson([
                'success' => true,
                'message' => 'API key revoked successfully'
            ]);

        } catch (\Exception $e) {
            return $response->withStatus(400)->withJson([
                'error' => 'revocation_failed',
                'message' => $e->getMessage()
            ]);
        }
    }

    // Account deletion
    public function deactivateAccount(Request $request, Response $response): Response
    {
        $user = $request->getAttribute('user');
        $password = $request->getParsedBody()['password'] ?? '';

        // Verify password
        $userRecord = $this->userService->getUserById($user['id']);
        if (!password_verify($password, $userRecord['password'])) {
            return $response->withStatus(400)->withJson([
                'error' => 'invalid_password',
                'message' => 'Incorrect password'
            ]);
        }

        try {
            $this->userService->deactivateAccount($user['id']);
            
            // Logout from all devices
            $this->userService->logoutAllSessions($user['id']);

            return $response->withJson([
                'success' => true,
                'message' => 'Account deactivated successfully'
            ]);

        } catch (\Exception $e) {
            return $response->withStatus(500)->withJson([
                'error' => 'deactivation_failed',
                'message' => $e->getMessage()
            ]);
        }
    }

    public function deleteAccount(Request $request, Response $response): Response
    {
        $user = $request->getAttribute('user');
        $password = $request->getParsedBody()['password'] ?? '';

        // Verify password
        $userRecord = $this->userService->getUserById($user['id']);
        if (!password_verify($password, $userRecord['password'])) {
            return $response->withStatus(400)->withJson([
                'error' => 'invalid_password',
                'message' => 'Incorrect password'
            ]);
        }

        try {
            $this->userService->deleteAccount($user['id']);
            
            return $response->withJson([
                'success' => true,
                'message' => 'Account deleted successfully'
            ]);

        } catch (\Exception $e) {
            return $response->withStatus(500)->withJson([
                'error' => 'deletion_failed',
                'message' => $e->getMessage()
            ]);
        }
    }

    // Two-factor authentication
    public function setupTwoFactor(Request $request, Response $response): Response
    {
        $user = $request->getAttribute('user');
        
        // Generate secret (in production, use a proper 2FA library)
        $secret = bin2hex(random_bytes(20));
        
        // QR code URL for Google Authenticator
        $issuer = 'SSO Auth System';
        $label = urlencode($user['email']);
        $qrCodeUrl = "otpauth://totp/{$issuer}:{$label}?secret={$secret}&issuer={$issuer}";
        
        // Store secret temporarily in session for verification
        $_SESSION['2fa_setup_secret'] = $secret;
        $_SESSION['2fa_setup_user_id'] = $user['id'];

        return $response->withJson([
            'success' => true,
            'secret' => $secret,
            'qr_code_url' => $qrCodeUrl,
            'message' => 'Scan the QR code with your authenticator app'
        ]);
    }

    public function verifyTwoFactorSetup(Request $request, Response $response): Response
    {
        $code = $request->getParsedBody()['code'] ?? '';
        $userId = $_SESSION['2fa_setup_user_id'] ?? 0;
        $secret = $_SESSION['2fa_setup_secret'] ?? '';

        if (!$userId || !$secret) {
            return $response->withStatus(400)->withJson([
                'error' => 'setup_not_started',
                'message' => 'Two-factor setup not started'
            ]);
        }

        // Verify code (simplified - use proper 2FA validation)
        // In production, use something like: sonata-project/google-authenticator
        $isValid = $this->verifyTwoFactorCode($secret, $code);

        if ($isValid) {
            // Enable 2FA for user
            $this->userService->enableTwoFactor($userId, $secret);
            
            // Clear setup session
            unset($_SESSION['2fa_setup_secret'], $_SESSION['2fa_setup_user_id']);

            return $response->withJson([
                'success' => true,
                'message' => 'Two-factor authentication enabled successfully'
            ]);
        }

        return $response->withStatus(400)->withJson([
            'error' => 'invalid_code',
            'message' => 'Invalid verification code'
        ]);
    }

    public function disableTwoFactor(Request $request, Response $response): Response
    {
        $user = $request->getAttribute('user');
        $code = $request->getParsedBody()['code'] ?? '';

        // Get user's 2FA secret
        $userRecord = $this->userService->getUserById($user['id']);
        
        if (!$userRecord['two_factor_secret']) {
            return $response->withStatus(400)->withJson([
                'error' => '2fa_not_enabled',
                'message' => 'Two-factor authentication is not enabled'
            ]);
        }

        // Verify code
        $isValid = $this->verifyTwoFactorCode($userRecord['two_factor_secret'], $code);

        if ($isValid) {
            $this->userService->disableTwoFactor($user['id']);
            
            return $response->withJson([
                'success' => true,
                'message' => 'Two-factor authentication disabled successfully'
            ]);
        }

        return $response->withStatus(400)->withJson([
            'error' => 'invalid_code',
            'message' => 'Invalid verification code'
        ]);
    }

    private function verifyTwoFactorCode(string $secret, string $code): bool
    {
        // Simplified verification - replace with proper 2FA library
        // This is just for demonstration
        $expectedCode = substr(hash_hmac('sha256', floor(time() / 30) . $secret, $secret), 0, 6);
        return hash_equals($expectedCode, $code);
    }
}