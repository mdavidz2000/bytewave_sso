<?php
namespace App\Admin\Controllers;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use App\Admin\Services\AdminAuthService;
use Slim\Views\Twig;

class AuthController
{
    private $view;
    private $authService;

    public function __construct(Twig $view, AdminAuthService $authService)
    {
        $this->view = $view;
        $this->authService = $authService;
    }

    public function authenticate(Request $request, Response $response): Response
    {
        $data = $request->getParsedBody();
        $username = $data['username'] ?? '';
        $password = $data['password'] ?? '';

        try {
            $result = $this->authService->authenticate($username, $password);

            if (!$result) {
                return $this->view->render($response->withStatus(401), 'admin/auth/login.twig', [
                    'error' => 'Invalid credentials'
                ]);
            }

            // Set secure cookie with token
            setcookie(
                'admin_token',
                $result['token'],
                [
                    'expires' => time() + (8 * 3600), // 8 hours
                    'path' => '/admin',
                    'secure' => isset($_SERVER['HTTPS']),
                    'httponly' => true,
                    'samesite' => 'Strict'
                ]
            );

            // Store admin info in session as backup
            if (session_status() === PHP_SESSION_NONE) {
                session_start();
            }
            $_SESSION['admin_user'] = $result['admin'];

            return $response->withHeader('Location', '/admin')
                ->withStatus(302);

        } catch (\Exception $e) {
            return $this->view->render($response->withStatus(500), 'admin/auth/login.twig', [
                'error' => 'Authentication failed: ' . $e->getMessage()
            ]);
        }
    }

    public function logout(Request $request, Response $response): Response
    {
        // Clear cookie
        setcookie('admin_token', '', time() - 3600, '/admin', '', isset($_SERVER['HTTPS']), true);

        // Clear session
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        session_destroy();

        return $response->withHeader('Location', '/admin/login')
            ->withStatus(302);
    }
}