<?php
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Routing\RouteCollectorProxy;
use App\Controllers\AuthController;
use App\Controllers\UserController;
use App\Middleware\AuthMiddleware;
use App\Admin\Middleware\AdminAuthMiddleware;

use App\Services\JWTService;

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

/*
// Admin routes (example)
$app->group('/admin', function (RouteCollectorProxy $group) {
    // Admin-specific routes here
})->add(new AuthMiddleware($container->get(JWTService::class)))
  ->add(AdminAuthMiddleware::class); // You would create this middleware*/