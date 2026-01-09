<?php
use Slim\Routing\RouteCollectorProxy;
use App\Admin\Controllers\DashboardController;
use App\Admin\Controllers\UsersController;
use App\Admin\Controllers\ApiKeysController;
use App\Admin\Controllers\SystemController;
use App\Admin\Controllers\AuthController;
use App\Admin\Middleware\AdminAuthMiddleware;
use App\Admin\Middleware\PermissionMiddleware;
use App\Admin\Services\AdminAuthService;

// Admin authentication routes (public)
$app->group('/admin', function (RouteCollectorProxy $group) {
    
    // Login page
    $group->get('/login', [DashboardController::class, 'loginPage'])
        ->setName('admin.login');
    
    // Authentication endpoint
    $group->post('/auth', [AuthController::class, 'authenticate'])
        ->setName('admin.auth');
    
    // Logout
    $group->get('/logout', [AuthController::class, 'logout'])
        ->setName('admin.logout');

})->add(function ($request, $handler) {
    // Add no-cache headers for admin pages
    $response = $handler->handle($request);
    return $response
        ->withHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
        ->withHeader('Pragma', 'no-cache');
});

// Protected admin routes
$app->group('/admin', function (RouteCollectorProxy $group) use ($container) {
    
    // Dashboard - this handles /admin and /admin/dashboard
    $group->get('', [DashboardController::class, 'dashboard'])
        ->setName('admin.dashboard');
    
    $group->get('/dashboard', [DashboardController::class, 'dashboard'])
        ->setName('admin.dashboard.full');

    // User Management
    $group->group('/users', function (RouteCollectorProxy $users) {
        $users->get('', [UsersController::class, 'index'])
            ->setName('admin.users.index');
        
        $users->get('/create', [UsersController::class, 'create'])
            ->setName('admin.users.create');
        
        $users->post('/create', [UsersController::class, 'create']);
        
        $users->get('/{id:[0-9]+}', [UsersController::class, 'view'])
            ->setName('admin.users.view');
        
        $users->get('/{id:[0-9]+}/edit', [UsersController::class, 'edit'])
            ->setName('admin.users.edit');
        
        $users->post('/{id:[0-9]+}/edit', [UsersController::class, 'edit']);
        
        $users->get('/{id:[0-9]+}/delete', [UsersController::class, 'delete'])
            ->setName('admin.users.delete');
        
        $users->get('/{id:[0-9]+}/impersonate', [UsersController::class, 'impersonate'])
            ->setName('admin.users.impersonate');
        
        $users->get('/export', [UsersController::class, 'export'])
            ->setName('admin.users.export');
    });

    // API Keys Management (if controller exists)
    if (class_exists('App\Admin\Controllers\ApiKeysController')) {
        $group->group('/api-keys', function (RouteCollectorProxy $keys) {
            $keys->get('', [ApiKeysController::class, 'index'])
                ->setName('admin.apikeys.index');
            
            $keys->get('/{id:[0-9]+}/revoke', [ApiKeysController::class, 'revoke'])
                ->setName('admin.apikeys.revoke');
            
            $keys->get('/stats', [ApiKeysController::class, 'stats'])
                ->setName('admin.apikeys.stats');
        });
    }

    // System Management (if controller exists)
    if (class_exists('App\Admin\Controllers\SystemController')) {
        $group->group('/system', function (RouteCollectorProxy $system) {
            $system->get('/logs', [SystemController::class, 'logs'])
                ->setName('admin.system.logs');
            
            $system->get('/logs/clear', [SystemController::class, 'clearLogs'])
                ->setName('admin.system.logs.clear');
            
            $system->get('/metrics', [SystemController::class, 'metrics'])
                ->setName('admin.system.metrics');
            
            $system->get('/settings', [SystemController::class, 'settings'])
                ->setName('admin.system.settings');
            
            $system->post('/settings', [SystemController::class, 'updateSettings']);
            
            $system->get('/backup', [SystemController::class, 'backup'])
                ->setName('admin.system.backup');
            
            $system->post('/backup/create', [SystemController::class, 'createBackup'])
                ->setName('admin.system.backup.create');
        });
    }

})->add(new AdminAuthMiddleware($container->get(AdminAuthService::class)))
  ->add(function ($request, $handler) {
    // Add admin-specific headers
    $response = $handler->handle($request);
    return $response
        ->withHeader('X-Frame-Options', 'DENY')
        ->withHeader('X-Content-Type-Options', 'nosniff')
        ->withHeader('X-XSS-Protection', '1; mode=block');
});