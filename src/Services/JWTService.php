<?php
namespace App\Services;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Exception;

class JWTService
{
    private $secret;
    private $algorithm;
    private $issuer;
    private $audience;

    public function __construct(array $config)
    {
        $this->secret = $config['secret'];
        $this->algorithm = $config['algorithm'];
        $this->issuer = $config['issuer'];
        $this->audience = $config['audience'];
    }

    public function generateAccessToken(array $user, string $clientId): string
    {
        $payload = [
            'iss' => $this->issuer,
            'aud' => $clientId,
            'iat' => time(),
            'exp' => time() + 3600, // 1 hour
            'sub' => $user['id'],
            'email' => $user['email'],
            'name' => $user['name'],
            'scopes' => $user['scopes'] ?? ['user'],
            'type' => 'access_token'
        ];

        return JWT::encode($payload, $this->secret, $this->algorithm);
    }

    public function generateRefreshToken(int $userId, string $clientId): string
    {
        $payload = [
            'iss' => $this->issuer,
            'aud' => $clientId,
            'iat' => time(),
            'exp' => time() + 2592000, // 30 days
            'sub' => $userId,
            'type' => 'refresh_token'
        ];

        return JWT::encode($payload, $this->secret, $this->algorithm);
    }

    public function validateToken(string $token): array
    {
        try {
            $decoded = JWT::decode($token, new Key($this->secret, $this->algorithm));
            return (array) $decoded;
        } catch (Exception $e) {
            throw new \Exception('Invalid token: ' . $e->getMessage());
        }
    }

    public function generateAuthCode(string $clientId, int $userId): string
    {
        $payload = [
            'iss' => $this->issuer,
            'aud' => $clientId,
            'iat' => time(),
            'exp' => time() + 300, // 5 minutes
            'sub' => $userId,
            'type' => 'auth_code'
        ];

        return JWT::encode($payload, $this->secret, $this->algorithm);
    }

    public function validateAuthCode(string $code, string $clientId): array
    {
        $decoded = $this->validateToken($code);
        
        if ($decoded['type'] !== 'auth_code') {
            throw new \Exception('Invalid token type');
        }
        
        if ($decoded['aud'] !== $clientId) {
            throw new \Exception('Invalid audience');
        }

        return $decoded;
    }
}