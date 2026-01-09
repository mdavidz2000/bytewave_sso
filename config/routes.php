<?php
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Routing\RouteCollectorProxy;
use App\Controllers\AuthController;
use App\Controllers\UserController;
use App\Middleware\AuthMiddleware;
use App\Services\JWTService;

// Test route to verify routing works
$app->get('/', function (Request $request, Response $response) {
    $html = '
    <!DOCTYPE html>
    <html>
    <head>
        <title>SSO Auth Server</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
            .card { background: #f5f5f5; padding: 20px; margin: 10px 0; border-radius: 8px; }
            h1 { color: #333; }
            a { color: #007bff; text-decoration: none; }
            a:hover { text-decoration: underline; }
            .status { color: #28a745; font-weight: bold; }
        </style>
    </head>
    <body>
        <h1>🔐 SSO Authentication Server</h1>
        <p class="status">✓ Server is running!</p>
        
        <div class="card">
            <h2>Admin Dashboard</h2>
            <p><a href="/admin/login">→ Go to Admin Login</a></p>
            <p>Default credentials: superadmin / Admin123!</p>
        </div>
        
        <div class="card">
            <h2>OAuth Endpoints</h2>
            <ul>
                <li><a href="/oauth/authorize?client_id=app1_client_id&redirect_uri=http://localhost:3000/auth/callback&state=test&response_type=code">Authorization Endpoint (Test)</a></li>
                <li>Token Endpoint: POST /oauth/token</li>
                <li>User Info: GET /api/user (requires token)</li>
            </ul>
        </div>
        
        <div class="card">
            <h2>User Endpoints</h2>
            <ul>
                <li>Register: POST /register</li>
                <li>Email Verification: GET /verify-email?token={token}</li>
                <li>Forgot Password: POST /forgot-password</li>
                <li>Reset Password: POST /reset-password</li>
            </ul>
        </div>
        
        <div class="card">
            <h2>Documentation</h2>
            <p>See README.md for complete API documentation</p>
        </div>
    </body>
    </html>
    ';
    
    $response->getBody()->write($html);
    return $response;
});

// Public routes
$app->post('/register', [UserController::class, 'register']);
$app->get('/verify-email', [UserController::class, 'verifyEmail']);
$app->post('/forgot-password', [UserController::class, 'requestPasswordReset']);
$app->post('/reset-password', [UserController::class, 'resetPassword']);

// Authorization endpoints
$app->get('/oauth/authorize', [AuthController::class, 'authorize']);
$app->post('/oauth/login', [AuthController::class, 'login']);
$app->post('/oauth/token', [AuthController::class, 'token']);

// Protected routes (require authentication)
$app->group('/api', function (RouteCollectorProxy $group) {
    
    // User profile
    $group->group('/user', function (RouteCollectorProxy $user) {
        $user->get('/profile', [UserController::class, 'getProfile']);
        $user->put('/profile', [UserController::class, 'updateProfile']);
        $user->post('/avatar', [UserController::class, 'uploadAvatar']);
        
        // Password management
        $user->post('/change-password', [UserController::class, 'changePassword']);
        
        // Preferences
        $user->get('/preferences', [UserController::class, 'getPreferences']);
        $user->put('/preferences', [UserController::class, 'updatePreferences']);
        
        // Sessions
        $user->get('/sessions', [UserController::class, 'getSessions']);
        $user->post('/sessions/revoke', [UserController::class, 'revokeSession']);
        $user->post('/logout-all', [UserController::class, 'logoutAll']);
        
        // API keys
        $user->get('/api-keys', [UserController::class, 'getApiKeys']);
        $user->post('/api-keys', [UserController::class, 'createApiKey']);
        $user->delete('/api-keys', [UserController::class, 'revokeApiKey']);
        
        // Two-factor authentication
        $user->post('/2fa/setup', [UserController::class, 'setupTwoFactor']);
        $user->post('/2fa/verify', [UserController::class, 'verifyTwoFactorSetup']);
        $user->post('/2fa/disable', [UserController::class, 'disableTwoFactor']);
        
        // Account management
        $user->post('/deactivate', [UserController::class, 'deactivateAccount']);
        $user->post('/delete', [UserController::class, 'deleteAccount']);
    });
    
    // Auth endpoints
    $group->get('/user', [AuthController::class, 'userInfo']);
    $group->post('/logout', [AuthController::class, 'logout']);
    
})->add(new AuthMiddleware($container->get(JWTService::class)));