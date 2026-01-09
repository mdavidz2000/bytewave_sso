<?php
use DI\Container;
use App\Services\JWTService;
use App\Services\UserService;
use App\Services\EmailService;
use App\Controllers\UserController;

use App\Admin\Services\AdminAuthService;

return function (Container $container) {
    // Load settings
    //$settings = require __DIR__ . '/settings.php';
    //$container->set('settings', $settings['settings']);

    // Load settings
    $allSettings = require __DIR__ . '/settings.php';
    $settings = $allSettings['settings']; // Access the inner 'settings' array
    
    $container->set('settings', $settings);

    // Database connection
    $container->set(PDO::class, function() use ($settings) {
        $db = $settings['database'];
        return new PDO(
            "mysql:host={$db['host']};dbname={$db['name']};charset=utf8mb4",
            $db['user'],
            $db['pass'],
            [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            ]
        );
    });

    // Register AdminAuthService
    $container->set(AdminAuthService::class, function(Container $c) {
        // Pass whatever dependencies your AdminAuthService needs
        // For example, it might need PDO or settings
        return new AdminAuthService(
            $c->get(PDO::class),
            $c->get('settings')['admin_secret'] ?? 'default'
        );
    });

    // Email Service
    $container->set(EmailService::class, function() use ($settings) {
        return new EmailService($settings['email'] ?? []);
    });

    // JWT Service
    $container->set(JWTService::class, function() use ($settings) {
        return new JWTService($settings['jwt']);
    });

    // User Service
    $container->set(UserService::class, function(Container $c) {
        return new UserService(
            $c->get(PDO::class),
            $c->get(EmailService::class)
        );
    });

    // Auth Controller
    $container->set(AuthController::class, function(Container $c) {
        $settings = $c->get('settings');
        return new AuthController(
            $c->get(JWTService::class),
            $c->get(UserService::class),
            $settings['apps'],
            $c->get('view')
        );
    });

    // User Controller
    $container->set(UserController::class, function(Container $c) {
        return new UserController(
            $c->get(UserService::class),
            $c->get(JWTService::class)
        );
    });
};