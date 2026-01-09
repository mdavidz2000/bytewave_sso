<?php
namespace App\Controllers;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use App\Services\JWTService;
use App\Services\UserService;
use Slim\Views\Twig;

class AuthController
{
    private $jwtService;
    private $userService;
    private $apps;
    private $view;

    public function __construct(JWTService $jwtService, UserService $userService, array $apps, Twig $view)
    {
        $this->jwtService = $jwtService;
        $this->userService = $userService;
        $this->apps = $apps;
        $this->view = $view;
    }

    public function authorize(Request $request, Response $response): Response
    {
        $queryParams = $request->getQueryParams();
        
        $clientId = $queryParams['client_id'] ?? '';
        $redirectUri = $queryParams['redirect_uri'] ?? '';
        $state = $queryParams['state'] ?? '';
        $responseType = $queryParams['response_type'] ?? 'code';

        // Validate client
        if (!isset($this->apps[$clientId])) {
            return $response->withStatus(400)->withJson([
                'error' => 'invalid_client',
                'message' => 'Invalid client ID'
            ]);
        }

        $appConfig = $this->apps[$clientId];

        // Validate redirect URI
        if ($redirectUri !== $appConfig['redirect_uri']) {
            return $response->withStatus(400)->withJson([
                'error' => 'invalid_redirect_uri',
                'message' => 'Invalid redirect URI'
            ]);
        }

        // Store in session for validation
        $_SESSION['auth'] = [
            'client_id' => $clientId,
            'redirect_uri' => $redirectUri,
            'state' => $state,
            'response_type' => $responseType
        ];

        // Render login page
        return $this->view->render($response, 'login.twig', [
            'client_id' => $clientId,
            'redirect_uri' => $redirectUri,
            'state' => $state
        ]);
    }

    public function login(Request $request, Response $response): Response
    {
        $data = $request->getParsedBody();
        $email = $data['email'] ?? '';
        $password = $data['password'] ?? '';

        // Validate user credentials
        $user = $this->userService->authenticate($email, $password);
        
        if (!$user) {
            return $response->withStatus(401)->withJson([
                'error' => 'invalid_credentials',
                'message' => 'Invalid email or password'
            ]);
        }

        // Get session data
        $authData = $_SESSION['auth'] ?? [];
        
        if (empty($authData)) {
            return $response->withStatus(400)->withJson([
                'error' => 'invalid_request',
                'message' => 'No authorization request found'
            ]);
        }

        // Generate authorization code
        $authCode = $this->jwtService->generateAuthCode(
            $authData['client_id'],
            $user['id']
        );

        // Redirect back to app with auth code
        $redirectUri = $authData['redirect_uri'] . '?' . http_build_query([
            'code' => $authCode,
            'state' => $authData['state']
        ]);

        return $response->withHeader('Location', $redirectUri)->withStatus(302);
    }

    public function token(Request $request, Response $response): Response
    {
        $data = $request->getParsedBody();
        
        $grantType = $data['grant_type'] ?? '';
        $clientId = $data['client_id'] ?? '';
        $clientSecret = $data['client_secret'] ?? '';
        $code = $data['code'] ?? '';
        $refreshToken = $data['refresh_token'] ?? '';

        // Validate client
        if (!isset($this->apps[$clientId]) || $this->apps[$clientId]['secret'] !== $clientSecret) {
            return $response->withStatus(401)->withJson([
                'error' => 'invalid_client',
                'message' => 'Invalid client credentials'
            ]);
        }

        switch ($grantType) {
            case 'authorization_code':
                return $this->handleAuthorizationCode($response, $code, $clientId);
                
            case 'refresh_token':
                return $this->handleRefreshToken($response, $refreshToken, $clientId);
                
            default:
                return $response->withStatus(400)->withJson([
                    'error' => 'unsupported_grant_type',
                    'message' => 'Unsupported grant type'
                ]);
        }
    }

    private function handleAuthorizationCode(Response $response, string $code, string $clientId): Response
    {
        try {
            // Validate auth code
            $decoded = $this->jwtService->validateAuthCode($code, $clientId);
            $userId = $decoded['sub'];

            // Get user data
            $user = $this->userService->getUserById($userId);
            
            if (!$user) {
                return $response->withStatus(400)->withJson([
                    'error' => 'invalid_grant',
                    'message' => 'User not found'
                ]);
            }

            // Generate tokens
            $accessToken = $this->jwtService->generateAccessToken($user, $clientId);
            $refreshToken = $this->jwtService->generateRefreshToken($userId, $clientId);

            return $response->withJson([
                'access_token' => $accessToken,
                'token_type' => 'Bearer',
                'expires_in' => 3600,
                'refresh_token' => $refreshToken,
                'user' => [
                    'id' => $user['id'],
                    'email' => $user['email'],
                    'name' => $user['name']
                ]
            ]);

        } catch (\Exception $e) {
            return $response->withStatus(400)->withJson([
                'error' => 'invalid_grant',
                'message' => $e->getMessage()
            ]);
        }
    }

    private function handleRefreshToken(Response $response, string $refreshToken, string $clientId): Response
    {
        try {
            // Validate refresh token
            $decoded = $this->jwtService->validateToken($refreshToken);
            
            if ($decoded['type'] !== 'refresh_token' || $decoded['aud'] !== $clientId) {
                throw new \Exception('Invalid refresh token');
            }

            $userId = $decoded['sub'];
            $user = $this->userService->getUserById($userId);
            
            if (!$user) {
                return $response->withStatus(400)->withJson([
                    'error' => 'invalid_grant',
                    'message' => 'User not found'
                ]);
            }

            // Generate new tokens
            $accessToken = $this->jwtService->generateAccessToken($user, $clientId);
            $newRefreshToken = $this->jwtService->generateRefreshToken($userId, $clientId);

            return $response->withJson([
                'access_token' => $accessToken,
                'token_type' => 'Bearer',
                'expires_in' => 3600,
                'refresh_token' => $newRefreshToken
            ]);

        } catch (\Exception $e) {
            return $response->withStatus(400)->withJson([
                'error' => 'invalid_grant',
                'message' => $e->getMessage()
            ]);
        }
    }

    public function userInfo(Request $request, Response $response): Response
    {
        $user = $request->getAttribute('user');
        
        return $response->withJson([
            'id' => $user['id'],
            'email' => $user['email'],
            'name' => $user['name'],
            'scopes' => $user['scopes']
        ]);
    }

    public function logout(Request $request, Response $response): Response
    {
        // In a production system, you might want to blacklist tokens here
        return $response->withJson([
            'message' => 'Successfully logged out'
        ]);
    }
}