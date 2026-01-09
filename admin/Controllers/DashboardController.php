<?php
namespace App\Admin\Controllers;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use App\Services\UserService;
use App\Services\JWTService;
use Slim\Views\Twig;

class DashboardController
{
    private $view;
    private $userService;
    private $jwtService;
    private $pdo;

    public function __construct(Twig $view, UserService $userService, JWTService $jwtService, \PDO $pdo)
    {
        $this->view = $view;
        $this->userService = $userService;
        $this->jwtService = $jwtService;
        $this->pdo = $pdo;
    }

    public function dashboard(Request $request, Response $response): Response
    {
        $admin = $request->getAttribute('admin');
        
        // Get dashboard statistics
        $stats = $this->getDashboardStats();
        
        // Get recent activity
        $recentActivity = $this->getRecentActivity();
        
        // Get system health
        $systemHealth = $this->getSystemHealth();

        return $this->view->render($response, 'admin/dashboard.twig', [
            'admin' => $admin,
            'stats' => $stats,
            'recent_activity' => $recentActivity,
            'system_health' => $systemHealth,
            'current_page' => 'dashboard'
        ]);
    }

    private function getDashboardStats(): array
    {
        $stats = [];

        // Total users
        $stmt = $this->pdo->query("SELECT COUNT(*) as count FROM users");
        $stats['total_users'] = $stmt->fetch()['count'];

        // Active users (last 30 days)
        $stmt = $this->pdo->prepare("
            SELECT COUNT(DISTINCT user_id) as count 
            FROM user_sessions 
            WHERE last_activity > DATE_SUB(NOW(), INTERVAL 30 DAY)
        ");
        $stmt->execute();
        $stats['active_users'] = $stmt->fetch()['count'];

        // New users this month
        $stmt = $this->pdo->prepare("
            SELECT COUNT(*) as count 
            FROM users 
            WHERE created_at > DATE_SUB(NOW(), INTERVAL 30 DAY)
        ");
        $stmt->execute();
        $stats['new_users_month'] = $stmt->fetch()['count'];

        // Total API keys
        $stmt = $this->pdo->query("SELECT COUNT(*) as count FROM api_keys WHERE is_active = TRUE");
        $stats['active_api_keys'] = $stmt->fetch()['count'];

        // Successful logins today
        $stmt = $this->pdo->prepare("
            SELECT COUNT(*) as count 
            FROM system_audit_logs 
            WHERE action = 'login_success' 
            AND created_at > CURDATE()
        ");
        $stmt->execute();
        $stats['logins_today'] = $stmt->fetch()['count'];

        // Failed logins today
        $stmt = $this->pdo->prepare("
            SELECT COUNT(*) as count 
            FROM system_audit_logs 
            WHERE action = 'login_failed' 
            AND created_at > CURDATE()
        ");
        $stmt->execute();
        $stats['failed_logins_today'] = $stmt->fetch()['count'];

        return $stats;
    }

    private function getRecentActivity(): array
    {
        $stmt = $this->pdo->prepare("
            SELECT 
                al.*,
                au.username as admin_username,
                au.name as admin_name,
                u.email as user_email,
                u.name as user_name
            FROM system_audit_logs al
            LEFT JOIN admin_users au ON al.admin_user_id = au.id
            LEFT JOIN users u ON al.user_id = u.id
            ORDER BY al.created_at DESC 
            LIMIT 20
        ");
        
        $stmt->execute();
        return $stmt->fetchAll(\PDO::FETCH_ASSOC);
    }

    private function getSystemHealth(): array
    {
        $health = [];

        // Database connection
        try {
            $this->pdo->query('SELECT 1');
            $health['database'] = 'healthy';
        } catch (\Exception $e) {
            $health['database'] = 'unhealthy';
        }

        // Disk space
        $freeSpace = disk_free_space(__DIR__);
        $totalSpace = disk_total_space(__DIR__);
        $health['disk_usage'] = round((1 - ($freeSpace / $totalSpace)) * 100, 2);

        // Memory usage
        $health['memory_usage'] = round(memory_get_usage(true) / 1024 / 1024, 2); // MB

        // Uptime (simplified)
        $health['uptime'] = $this->getUptime();

        return $health;
    }

    private function getUptime(): string
    {
        if (PHP_OS === 'Linux') {
            $uptime = @file_get_contents('/proc/uptime');
            if ($uptime !== false) {
                $uptime = floatval(explode(' ', $uptime)[0]);
                $days = floor($uptime / 86400);
                $hours = floor(($uptime % 86400) / 3600);
                return sprintf('%d days, %d hours', $days, $hours);
            }
        }
        return 'Unknown';
    }

    public function loginPage(Request $request, Response $response): Response
    {
        return $this->view->render($response, 'admin/auth/login.twig', [
            'error' => $request->getQueryParams()['error'] ?? null
        ]);
    }
}