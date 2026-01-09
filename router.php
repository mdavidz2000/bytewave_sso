<?php
/**
 * Router for PHP built-in web server
 * This file handles all requests and routes them through index.php
 */

// Get the requested URI
$uri = urldecode(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH));

// Check if it's a static file in the public directory
$filePath = __DIR__ . '/public' . $uri;

// Only serve if it's an actual file (not a directory) and exists
if ($uri !== '/' && is_file($filePath)) {
    return false;  // Let PHP's built-in server serve the file
}

// All other requests go through index.php
chdir(__DIR__ . '/public');
require __DIR__ . '/public/index.php';