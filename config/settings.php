<?php
return [
    'settings' => [
        'displayErrorDetails' => $_ENV['APP_ENV'] === 'development',
        'addContentLengthHeader' => false,
        'jwt' => [
            'secret' => $_ENV['JWT_SECRET'],
            'algorithm' => 'HS256',
            'issuer' => $_ENV['APP_URL'],
            'audience' => $_ENV['APP_URL'],
            'expiration' => 3600, // 1 hour
            'refresh_expiration' => 2592000, // 30 days
        ],
        'database' => [
            'host' => $_ENV['DB_HOST'],
            'name' => $_ENV['DB_NAME'],
            'user' => $_ENV['DB_USER'],
            'pass' => $_ENV['DB_PASS'],
        ],
        'apps' => [
            'app1' => [
                'id' => $_ENV['APP1_CLIENT_ID'],
                'secret' => $_ENV['APP1_CLIENT_SECRET'],
                'redirect_uri' => $_ENV['APP1_REDIRECT_URI'],
            ],
            'app2' => [
                'id' => $_ENV['APP2_CLIENT_ID'],
                'secret' => $_ENV['APP2_CLIENT_SECRET'],
                'redirect_uri' => $_ENV['APP2_REDIRECT_URI'],
            ],
        ],
    ],
];