<?php

declare(strict_types=1);

/**
 * Front controller for the blind dead-drop server.
 *
 * Works as a router script for the PHP built-in server
 * (`php -S host:port public/index.php`) and as the document-root entry point
 * behind php-fpm + nginx. Configuration comes from the environment (see Config).
 */

use Bdd\Config;
use Bdd\Server;

// Locate the autoloader whether this file runs from the dev `public/` subdir or
// sits at the deployed web root (public_html) with `src/` beside it.
(static function (): void {
    foreach ([__DIR__ . '/../src/autoload.php', __DIR__ . '/src/autoload.php'] as $candidate) {
        if (is_file($candidate)) {
            require $candidate;
            return;
        }
    }
    http_response_code(500);
    exit("autoload.php not found\n");
})();

// Blindness at the header level: never advertise the PHP version.
ini_set('expose_php', '0');
header_remove('X-Powered-By');

$config = Config::fromEnv();
$server = new Server($config->store(), $config->defaultTtl);

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$uri = $_SERVER['REQUEST_URI'] ?? '/';
$path = parse_url($uri, PHP_URL_PATH) ?: '/';
parse_str((string) parse_url($uri, PHP_URL_QUERY), $query);
$body = file_get_contents('php://input') ?: '';

$server->handle($method, $path, $query, $body);
