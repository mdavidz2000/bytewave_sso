<?php
namespace App\Admin\Middleware;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;
use App\Admin\Services\AdminAuthService;
use Slim\Psr7\Response as SlimResponse;

class AdminAuthMiddleware
{
    private $authService;
    private $excludedRoutes = ['/admin/login', '/admin/auth'];

    public function __construct(AdminAuthService $authService)
    {
        $this->authService = $authService;
    }

    public function __invoke(Request $request, RequestHandler $handler): Response
    {
        $path = $request->getUri()->getPath();

        // Check if route is excluded
        foreach ($this->excludedRoutes as $excluded) {
            if (strpos($path, $excluded) === 0) {
                return $handler->handle($request);
            }
        }

        // Check for token in cookies or headers
        $token = $this->extractToken($request);

        if (!$token) {
            return $this->redirectToLogin($request);
        }

        try {
            $adminData = $this->authService->validateToken($token);
            
            // Add admin data to request
            $request = $request->withAttribute('admin', $adminData);
            
            // Refresh token if close to expiry (optional)
            if ($adminData['exp'] - time() < 1800) { // 30 minutes left
                $this->refreshToken($request);
            }

            return $handler->handle($request);

        } catch (\Exception $e) {
            // Clear invalid token
            $this->clearToken();
            return $this->redirectToLogin($request, 'Session expired. Please login again.');
        }
    }

    private function extractToken(Request $request): ?string
    {
        // Try cookie first
        $cookies = $request->getCookieParams();
        if (isset($cookies['admin_token'])) {
            return $cookies['admin_token'];
        }

        // Try Authorization header
        $authHeader = $request->getHeaderLine('Authorization');
        if (preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
            return $matches[1];
        }

        return null;
    }

    private function redirectToLogin(Request $request, string $message = ''): Response
    {
        // If AJAX request, return JSON
        if ($request->hasHeader('X-Requested-With') && 
            $request->getHeaderLine('X-Requested-With') === 'XMLHttpRequest') {
            
            $response = new SlimResponse();
            $response->getBody()->write(json_encode([
                'error' => 'unauthorized',
                'message' => $message ?: 'Authentication required',
                'redirect' => '/admin/login'
            ]));
            
            return $response->withStatus(401)
                ->withHeader('Content-Type', 'application/json');
        }

        // Regular request, redirect to login
        $response = new SlimResponse();
        return $response->withHeader('Location', '/admin/login')
            ->withStatus(302);
    }

    private function clearToken(): void
    {
        if (PHP_SAPI !== 'cli') {
            setcookie('admin_token', '', time() - 3600, '/admin', '', true, true);
        }
    }

    private function refreshToken(Request $request): void
    {
        // Implement token refresh logic here
        // You could set a new cookie with updated expiry
    }
}