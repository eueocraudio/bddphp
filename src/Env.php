<?php

declare(strict_types=1);

namespace Bdd;

/**
 * Minimal KEY=VALUE .env loader (no dependency on a dotenv package).
 *
 * Shared hosting (the production target) usually can't export real process
 * environment variables, so the deployed app reads its database settings from a
 * `.env` file placed next to the code — kept out of git. This loader populates
 * getenv()/$_ENV from such a file without overwriting variables already set in
 * the real environment (so local dev can still override).
 */
final class Env
{
    /** Load $path into the environment if it exists. Returns the parsed pairs. */
    public static function load(string $path): array
    {
        if (!is_file($path) || !is_readable($path)) {
            return [];
        }
        $pairs = [];
        foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            if (!preg_match('/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/', $line, $m)) {
                continue;
            }
            $key = $m[1];
            $value = self::unquote(trim($m[2]));
            $pairs[$key] = $value;
            if (getenv($key) === false) {
                putenv("$key=$value");
                $_ENV[$key] = $value;
            }
        }
        return $pairs;
    }

    private static function unquote(string $v): string
    {
        if (strlen($v) >= 2) {
            $first = $v[0];
            if (($first === '"' || $first === "'") && str_ends_with($v, $first)) {
                return substr($v, 1, -1);
            }
        }
        return $v;
    }
}
