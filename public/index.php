<?php

// Start session
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Error reporting
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

// Set base path for proper routing
$app->setBasePath('');

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
$dependencies = require __DIR__ . '/../config/dependencies.php';
$dependencies($container);

// Load routes
require __DIR__ . '/../config/routes.php';
require __DIR__ . '/../config/admin-routes.php';

$app->run();