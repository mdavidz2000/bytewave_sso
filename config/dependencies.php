<?php
use DI\Container;
use Slim\Views\Twig;
use Slim\Views\TwigMiddleware;
use App\Services\JWTService;
use App\Services\UserService;
use App\Services\EmailService;
use App\Controllers\AuthController;
use App\Controllers\UserController;
use App\Admin\Services\AdminAuthService;
use App\Admin\Controllers\DashboardController;
use App\Admin\Controllers\UsersController;
use App\Admin\Controllers\AuthController as AdminAuthController;

return function (Container $container) {
    // Load settings
    $allSettings = require __DIR__ . '/settings.php';
    $settings = $allSettings['settings'];
    
    $container->set('settings', $settings);

    // Database connection
    $container->set(PDO::class, function() use ($settings) {
        $db = $settings['database'];
        $dsn = "mysql:host={$db['host']};dbname={$db['name']};charset=utf8mb4";
        $pdo = new PDO($dsn, $db['user'], $db['pass'], [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
        return $pdo;
    });

    // Twig View - Add BOTH template paths
    $container->set('view', function() {
        $twig = Twig::create([
            __DIR__ . '/../templates',       // Main templates
            __DIR__ . '/../admin/templates'  // Admin templates
        ], [
            'cache' => false, // Enable in production: __DIR__ . '/../cache'
        ]);
        
        // Add Twig extensions if needed
        $twig->getEnvironment()->addGlobal('app_name', 'SSO Auth System');
        
        return $twig;
    });

    // Email Service
    $container->set(EmailService::class, function() use ($settings) {
        $emailConfig = [
            'driver' => $_ENV['EMAIL_DRIVER'] ?? 'smtp',
            'host' => $_ENV['EMAIL_HOST'] ?? 'smtp.gmail.com',
            'port' => $_ENV['EMAIL_PORT'] ?? 587,
            'username' => $_ENV['EMAIL_USERNAME'] ?? '',
            'password' => $_ENV['EMAIL_PASSWORD'] ?? '',
            'encryption' => $_ENV['EMAIL_ENCRYPTION'] ?? 'tls',
            'from_email' => $_ENV['EMAIL_FROM'] ?? 'noreply@example.com',
            'from_name' => $_ENV['EMAIL_FROM_NAME'] ?? 'SSO Auth System',
            'app_url' => $_ENV['APP_URL'] ?? 'http://localhost:8079'
        ];
        return new EmailService($emailConfig);
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

    // Admin Auth Service
    $container->set(AdminAuthService::class, function(Container $c) use ($settings) {
        return new AdminAuthService(
            $c->get(PDO::class),
            $settings['jwt']['secret']
        );
    });

    // Auth Controller
    $container->set(AuthController::class, function(Container $c) use ($settings) {
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

    // Admin Dashboard Controller
    $container->set(DashboardController::class, function(Container $c) {
        return new DashboardController(
            $c->get('view'),
            $c->get(UserService::class),
            $c->get(JWTService::class),
            $c->get(PDO::class)
        );
    });

    // Admin Users Controller
    $container->set(UsersController::class, function(Container $c) {
        return new UsersController(
            $c->get('view'),
            $c->get(UserService::class),
            $c->get(PDO::class)
        );
    });

    // Admin Auth Controller
    $container->set(AdminAuthController::class, function(Container $c) {
        return new AdminAuthController(
            $c->get('view'),
            $c->get(AdminAuthService::class)
        );
    });
};