<?php

declare(strict_types=1);

/**
 * Bootstrap autoloading for bddphp.
 *
 * Prefers Composer's autoloader when present (it also wires up dev tools like
 * PHPUnit), but falls back to a tiny PSR-4 loader for the `Bdd\` namespace so
 * the server and CLI run straight from a fresh checkout with no `composer
 * install` — the package itself depends only on bundled PHP extensions.
 */

$composer = __DIR__ . '/../vendor/autoload.php';
if (is_file($composer)) {
    require $composer;
    return;
}

spl_autoload_register(static function (string $class): void {
    $prefix = 'Bdd\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }
    $relative = substr($class, strlen($prefix));
    $path = __DIR__ . '/' . str_replace('\\', '/', $relative) . '.php';
    if (is_file($path)) {
        require $path;
    }
});
