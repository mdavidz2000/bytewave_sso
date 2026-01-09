<?php
namespace App\Middleware;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;
use App\Services\JWTService;

class AuthMiddleware
{
    private $jwtService;

    public function __construct(JWTService $jwtService)
    {
        $this->jwtService = $jwtService;
    }

    public function __invoke(Request $request, RequestHandler $handler): Response
    {
        $authHeader = $request->getHeaderLine('Authorization');
        
        if (empty($authHeader) || !preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
            return $this->unauthorizedResponse('No token provided');
        }

        $token = $matches[1];

        try {
            $decoded = $this->jwtService->validateToken($token);
            
            // Check token type
            if ($decoded['type'] !== 'access_token') {
                return $this->unauthorizedResponse('Invalid token type');
            }

            // Add user data to request
            $request = $request->withAttribute('user', [
                'id' => $decoded['sub'],
                'email' => $decoded['email'],
                'name' => $decoded['name'],
                'scopes' => $decoded['scopes']
            ]);

            return $handler->handle($request);

        } catch (\Exception $e) {
            return $this->unauthorizedResponse('Invalid token: ' . $e->getMessage());
        }
    }

    private function unauthorizedResponse(string $message): Response
    {
        $response = new \Slim\Psr7\Response();
        $response->getBody()->write(json_encode([
            'error' => 'unauthorized',
            'message' => $message
        ]));
        
        return $response->withStatus(401)
            ->withHeader('Content-Type', 'application/json');
    }
}