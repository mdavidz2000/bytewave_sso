<?php
namespace App\Admin\Controllers;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use App\Services\UserService;
use Slim\Views\Twig;
use Respect\Validation\Validator as v;

class UsersController
{
    private $view;
    private $userService;
    private $pdo;

    public function __construct(Twig $view, UserService $userService, \PDO $pdo)
    {
        $this->view = $view;
        $this->userService = $userService;
        $this->pdo = $pdo;
    }

    public function index(Request $request, Response $response): Response
    {
        $admin = $request->getAttribute('admin');
        $queryParams = $request->getQueryParams();
        
        $page = max(1, (int)($queryParams['page'] ?? 1));
        $perPage = (int)($queryParams['per_page'] ?? 20);
        
        $filters = [
            'search' => $queryParams['search'] ?? '',
            'status' => $queryParams['status'] ?? '',
            'verified' => $queryParams['verified'] ?? '',
            'role' => $queryParams['role'] ?? '',
            'date_from' => $queryParams['date_from'] ?? '',
            'date_to' => $queryParams['date_to'] ?? ''
        ];

        // Get all roles for filter dropdown
        $roles = $this->getAllRoles();

        // Get users from SSO database
        $usersResult = $this->userService->searchUsers($filters, $page, $perPage);

        return $this->view->render($response, 'admin/users/list.twig', [
            'admin' => $admin,
            'users' => $usersResult['users'],
            'pagination' => [
                'page' => $usersResult['page'],
                'per_page' => $usersResult['per_page'],
                'total' => $usersResult['total'],
                'total_pages' => $usersResult['total_pages']
            ],
            'filters' => $filters,
            'roles' => $roles,
            'current_page' => 'users'
        ]);
    }

    public function view(Request $request, Response $response, array $args): Response
    {
        $admin = $request->getAttribute('admin');
        $userId = (int)$args['id'];

        try {
            $user = $this->userService->getUserById($userId);
            $roles = $this->getAllRoles();
            $userRoles = $this->getUserRoles($userId);

            // Get user activity
            $activity = $this->getUserActivity($userId);

            return $this->view->render($response, 'admin/users/view.twig', [
                'admin' => $admin,
                'user' => $user,
                'roles' => $roles,
                'user_roles' => $userRoles,
                'activity' => $activity,
                'current_page' => 'users'
            ]);

        } catch (\Exception $e) {
            // Redirect with error
            return $response->withHeader('Location', '/admin/users?error=' . urlencode($e->getMessage()))
                ->withStatus(302);
        }
    }

    public function create(Request $request, Response $response): Response
    {
        $admin = $request->getAttribute('admin');
        $roles = $this->getAllRoles();

        if ($request->getMethod() === 'POST') {
            $data = $request->getParsedBody();

            try {
                // Validate input
                $validator = v::key('email', v::email()->notEmpty())
                    ->key('password', v::stringType()->length(8, null)->notEmpty())
                    ->key('name', v::stringType()->notEmpty());

                $validator->assert($data);

                // Create user via UserService
                $userData = [
                    'email' => $data['email'],
                    'password' => $data['password'],
                    'name' => $data['name'],
                    'phone' => $data['phone'] ?? null,
                    'is_active' => isset($data['is_active']),
                    'email_verified' => isset($data['email_verified'])
                ];

                // Note: We need to extend UserService to handle admin creation
                // For now, we'll do it directly
                $user = $this->createUserDirectly($userData, $data['roles'] ?? []);

                // Log admin action
                $this->logAdminAction($admin['sub'], 'user_create', 'user', $user['id'], [
                    'email' => $user['email'],
                    'name' => $user['name']
                ]);

                return $response->withHeader('Location', '/admin/users/' . $user['id'])
                    ->withStatus(302);

            } catch (\Exception $e) {
                return $this->view->render($response, 'admin/users/create.twig', [
                    'admin' => $admin,
                    'roles' => $roles,
                    'form_data' => $data,
                    'error' => $e->getMessage(),
                    'current_page' => 'users'
                ]);
            }
        }

        return $this->view->render($response, 'admin/users/create.twig', [
            'admin' => $admin,
            'roles' => $roles,
            'current_page' => 'users'
        ]);
    }

    public function edit(Request $request, Response $response, array $args): Response
    {
        $admin = $request->getAttribute('admin');
        $userId = (int)$args['id'];
        $roles = $this->getAllRoles();

        try {
            $user = $this->userService->getUserById($userId);
            $userRoles = $this->getUserRoles($userId);

            if ($request->getMethod() === 'POST') {
                $data = $request->getParsedBody();

                // Update user
                $updateData = [
                    'email' => $data['email'],
                    'name' => $data['name'],
                    'phone' => $data['phone'] ?? null,
                    'is_active' => isset($data['is_active']),
                    'email_verified' => isset($data['email_verified']),
                    'roles' => $data['roles'] ?? []
                ];

                // Update via UserService or directly
                $updatedUser = $this->updateUserDirectly($userId, $updateData);

                // Log admin action
                $this->logAdminAction($admin['sub'], 'user_update', 'user', $userId, [
                    'changes' => array_diff_assoc($updateData, $user)
                ]);

                return $response->withHeader('Location', '/admin/users/' . $userId)
                    ->withStatus(302);
            }

            return $this->view->render($response, 'admin/users/edit.twig', [
                'admin' => $admin,
                'user' => $user,
                'roles' => $roles,
                'user_roles' => $userRoles,
                'current_page' => 'users'
            ]);

        } catch (\Exception $e) {
            return $response->withHeader('Location', '/admin/users?error=' . urlencode($e->getMessage()))
                ->withStatus(302);
        }
    }

    public function delete(Request $request, Response $response, array $args): Response
    {
        $admin = $request->getAttribute('admin');
        $userId = (int)$args['id'];

        try {
            // Get user info before deletion for logging
            $user = $this->userService->getUserById($userId);

            // Delete user
            $this->userService->deleteAccount($userId);

            // Log admin action
            $this->logAdminAction($admin['sub'], 'user_delete', 'user', $userId, [
                'email' => $user['email'],
                'name' => $user['name']
            ]);

            return $response->withHeader('Location', '/admin/users?success=User+deleted')
                ->withStatus(302);

        } catch (\Exception $e) {
            return $response->withHeader('Location', '/admin/users?error=' . urlencode($e->getMessage()))
                ->withStatus(302);
        }
    }

    public function impersonate(Request $request, Response $response, array $args): Response
    {
        $admin = $request->getAttribute('admin');
        $userId = (int)$args['id'];

        try {
            $user = $this->userService->getUserById($userId);
            
            if (!$user['is_active']) {
                throw new Exception('Cannot impersonate inactive user');
            }

            // Generate impersonation token using JWTService
            $impersonationToken = $this->jwtService->generateImpersonationToken($user, $admin['sub']);

            // Log admin action
            $this->logAdminAction($admin['sub'], 'user_impersonate', 'user', $userId, [
                'email' => $user['email']
            ]);

            // Redirect to main app with impersonation token
            $redirectUrl = $_ENV['APP_URL'] . '/auth/impersonate?token=' . $impersonationToken;
            
            return $response->withHeader('Location', $redirectUrl)
                ->withStatus(302);

        } catch (\Exception $e) {
            return $response->withHeader('Location', '/admin/users?error=' . urlencode($e->getMessage()))
                ->withStatus(302);
        }
    }

    public function export(Request $request, Response $response): Response
    {
        $admin = $request->getAttribute('admin');
        $format = $request->getQueryParams()['format'] ?? 'csv';

        $filters = [
            'search' => $request->getQueryParams()['search'] ?? '',
            'status' => $request->getQueryParams()['status'] ?? ''
        ];

        try {
            $data = $this->userService->exportUsers($filters, $format);

            // Log admin action
            $this->logAdminAction($admin['sub'], 'users_export', 'system', null, [
                'format' => $format,
                'filters' => $filters
            ]);

            $response->getBody()->write($data);
            
            if ($format === 'csv') {
                return $response->withHeader('Content-Type', 'text/csv')
                    ->withHeader('Content-Disposition', 'attachment; filename="users_' . date('Y-m-d') . '.csv"');
            } else {
                return $response->withHeader('Content-Type', 'application/json')
                    ->withHeader('Content-Disposition', 'attachment; filename="users_' . date('Y-m-d') . '.json"');
            }

        } catch (\Exception $e) {
            return $response->withHeader('Location', '/admin/users?error=' . urlencode($e->getMessage()))
                ->withStatus(302);
        }
    }

    // Helper methods
    private function getAllRoles(): array
    {
        $stmt = $this->pdo->query("SELECT id, name FROM roles ORDER BY name");
        return $stmt->fetchAll(\PDO::FETCH_ASSOC);
    }

    private function getUserRoles(int $userId): array
    {
        $stmt = $this->pdo->prepare("
            SELECT r.id 
            FROM roles r
            JOIN user_roles ur ON r.id = ur.role_id
            WHERE ur.user_id = :user_id
        ");
        
        $stmt->execute(['user_id' => $userId]);
        return $stmt->fetchAll(\PDO::FETCH_COLUMN);
    }

    private function getUserActivity(int $userId): array
    {
        $stmt = $this->pdo->prepare("
            SELECT * FROM system_audit_logs 
            WHERE user_id = :user_id 
            ORDER BY created_at DESC 
            LIMIT 50
        ");
        
        $stmt->execute(['user_id' => $userId]);
        return $stmt->fetchAll(\PDO::FETCH_ASSOC);
    }

    private function createUserDirectly(array $data, array $roleIds): array
    {
        $this->pdo->beginTransaction();

        try {
            // Hash password
            $hashedPassword = password_hash($data['password'], PASSWORD_DEFAULT);

            // Insert user
            $stmt = $this->pdo->prepare("
                INSERT INTO users (email, password, name, phone, is_active, email_verified_at) 
                VALUES (:email, :password, :name, :phone, :is_active, :email_verified_at)
            ");
            
            $stmt->execute([
                'email' => $data['email'],
                'password' => $hashedPassword,
                'name' => $data['name'],
                'phone' => $data['phone'] ?? null,
                'is_active' => $data['is_active'] ? 1 : 0,
                'email_verified_at' => $data['email_verified'] ? date('Y-m-d H:i:s') : null
            ]);

            $userId = $this->pdo->lastInsertId();

            // Assign roles
            foreach ($roleIds as $roleId) {
                $stmt = $this->pdo->prepare("
                    INSERT INTO user_roles (user_id, role_id) 
                    VALUES (:user_id, :role_id)
                ");
                
                $stmt->execute(['user_id' => $userId, 'role_id' => $roleId]);
            }

            $this->pdo->commit();

            return $this->userService->getUserById($userId);

        } catch (\Exception $e) {
            $this->pdo->rollBack();
            throw $e;
        }
    }

    private function updateUserDirectly(int $userId, array $data): array
    {
        $this->pdo->beginTransaction();

        try {
            // Update user fields
            $updateFields = [];
            $params = ['id' => $userId];

            if (isset($data['email'])) {
                // Check email uniqueness
                $stmt = $this->pdo->prepare("
                    SELECT id FROM users 
                    WHERE email = :email AND id != :id
                ");
                
                $stmt->execute(['email' => $data['email'], 'id' => $userId]);
                
                if ($stmt->fetch()) {
                    throw new Exception('Email already in use');
                }
                
                $updateFields[] = "email = :email";
                $params['email'] = $data['email'];
            }

            if (isset($data['name'])) {
                $updateFields[] = "name = :name";
                $params['name'] = $data['name'];
            }

            if (isset($data['phone'])) {
                $updateFields[] = "phone = :phone";
                $params['phone'] = $data['phone'];
            }

            if (isset($data['is_active'])) {
                $updateFields[] = "is_active = :is_active";
                $params['is_active'] = $data['is_active'] ? 1 : 0;
            }

            if (isset($data['email_verified'])) {
                $updateFields[] = "email_verified_at = :email_verified_at";
                $params['email_verified_at'] = $data['email_verified'] ? date('Y-m-d H:i:s') : null;
            }

            if (!empty($updateFields)) {
                $setClause = implode(', ', $updateFields);
                $stmt = $this->pdo->prepare("
                    UPDATE users 
                    SET $setClause, updated_at = NOW() 
                    WHERE id = :id
                ");
                
                $stmt->execute($params);
            }

            // Update roles if provided
            if (isset($data['roles'])) {
                // Remove existing roles
                $stmt = $this->pdo->prepare("
                    DELETE FROM user_roles 
                    WHERE user_id = :user_id
                ");
                
                $stmt->execute(['user_id' => $userId]);

                // Add new roles
                foreach ($data['roles'] as $roleId) {
                    $stmt = $this->pdo->prepare("
                        INSERT INTO user_roles (user_id, role_id) 
                        VALUES (:user_id, :role_id)
                    ");
                    
                    $stmt->execute(['user_id' => $userId, 'role_id' => $roleId]);
                }
            }

            $this->pdo->commit();

            return $this->userService->getUserById($userId);

        } catch (\Exception $e) {
            $this->pdo->rollBack();
            throw $e;
        }
    }

    private function logAdminAction(int $adminId, string $action, string $resourceType, ?int $resourceId, array $details = []): void
    {
        $stmt = $this->pdo->prepare("
            INSERT INTO system_audit_logs 
            (admin_user_id, action, resource_type, resource_id, details, ip_address, user_agent) 
            VALUES (:admin_id, :action, :resource_type, :resource_id, :details, :ip, :ua)
        ");
        
        $stmt->execute([
            'admin_id' => $adminId,
            'action' => $action,
            'resource_type' => $resourceType,
            'resource_id' => $resourceId,
            'details' => json_encode($details),
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'ua' => $_SERVER['HTTP_USER_AGENT'] ?? ''
        ]);
    }
}