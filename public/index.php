<?php

error_reporting(E_ALL);
ini_set('display_errors', '1');
use Slim\Factory\AppFactory;
use DI\Container;

require __DIR__ . '/../vendor/autoload.php';

// Load environment
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/../');
$dotenv->load();

// Create container
$container = new Container();
AppFactory::setContainer($container);

// Create app
$app = AppFactory::create();

// Add middleware
$app->addBodyParsingMiddleware();
$app->addRoutingMiddleware();

// Error middleware
$errorMiddleware = $app->addErrorMiddleware(
    $_ENV['APP_ENV'] === 'development',
    true,
    true
);

// Configure dependencies
//require __DIR__ . '/../config/dependencies.php';
// FIX: Capture the returned function and execute it
$dependencies = require __DIR__ . '/../config/dependencies.php';
$dependencies($container);

// Main SSO routes
require __DIR__ . '/../config/routes.php';

// Admin dashboard routes
require __DIR__ . '/../config/admin-routes.php';

$app->run();