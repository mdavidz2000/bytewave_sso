<?php
return [
    'settings' => [
        'displayErrorDetails' => $_ENV['APP_ENV'] === 'development',
        'addContentLengthHeader' => false,
        
        'jwt' => [
            'secret' => $_ENV['JWT_SECRET'] ?? 'your-super-secret-jwt-key-change-this',
            'algorithm' => 'HS256',
            'issuer' => $_ENV['APP_URL'] ?? 'http://localhost:8079',
            'audience' => $_ENV['APP_URL'] ?? 'http://localhost:8079',
            'expiration' => 3600, // 1 hour
            'refresh_expiration' => 2592000, // 30 days
        ],
        
        'database' => [
            'host' => $_ENV['DB_HOST'] ?? 'localhost',
            'name' => $_ENV['DB_NAME'] ?? 'bytewave_sso',
            'user' => $_ENV['DB_USER'] ?? 'root',
            'pass' => $_ENV['DB_PASS'] ?? '',
        ],
        
        'apps' => [
            $_ENV['APP1_CLIENT_ID'] ?? 'app1_client_id' => [
                'id' => $_ENV['APP1_CLIENT_ID'] ?? 'app1_client_id',
                'secret' => $_ENV['APP1_CLIENT_SECRET'] ?? 'app1_secret_key',
                'redirect_uri' => $_ENV['APP1_REDIRECT_URI'] ?? 'http://localhost:3000/auth/callback',
                'name' => 'Application 1',
            ],
            $_ENV['APP2_CLIENT_ID'] ?? 'app2_client_id' => [
                'id' => $_ENV['APP2_CLIENT_ID'] ?? 'app2_client_id',
                'secret' => $_ENV['APP2_CLIENT_SECRET'] ?? 'app2_secret_key',
                'redirect_uri' => $_ENV['APP2_REDIRECT_URI'] ?? 'http://localhost:3001/auth/callback',
                'name' => 'Application 2',
            ],
        ],
        
        'email' => [
            'driver' => $_ENV['EMAIL_DRIVER'] ?? 'smtp',
            'host' => $_ENV['EMAIL_HOST'] ?? 'smtp.gmail.com',
            'port' => $_ENV['EMAIL_PORT'] ?? 587,
            'username' => $_ENV['EMAIL_USERNAME'] ?? '',
            'password' => $_ENV['EMAIL_PASSWORD'] ?? '',
            'encryption' => $_ENV['EMAIL_ENCRYPTION'] ?? 'tls',
            'from_email' => $_ENV['EMAIL_FROM'] ?? 'noreply@example.com',
            'from_name' => $_ENV['EMAIL_FROM_NAME'] ?? 'SSO Auth System',
            'app_url' => $_ENV['APP_URL'] ?? 'http://localhost:8079'
        ],
        
        'admin_secret' => $_ENV['JWT_SECRET'] ?? 'your-super-secret-jwt-key-change-this',
    ],
];