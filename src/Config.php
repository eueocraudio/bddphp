<?php

declare(strict_types=1);

namespace Bdd;

/**
 * Server configuration read from the environment. Used by the front controller
 * and the CLI `serve`. Storage is a directory of blob files — there is no
 * database, so no credentials to keep out of code or argv.
 *
 *   BDDPHP_DATA_DIR    directory holding the slot files (default: ./data beside
 *                      the code). Must be writable and not web-servable — the
 *                      shipped .htaccess denies it.
 *   BDDPHP_DEFAULT_TTL default entry lifetime in seconds, snapped to a bucket
 *
 * fromEnv() first loads a local `.env` (next to the deployed code) via Env, so
 * a shared host that can't set real env vars still gets configured. It does NOT
 * read ~/.env — that file holds the deploy credentials and is consumed only by
 * the deploy script.
 */
final class Config
{
    public function __construct(
        public readonly string $dataDir,
        public readonly int $defaultTtl,
    ) {
    }

    public static function fromEnv(): self
    {
        // Load a `.env` sitting next to the code (project root in dev, or the
        // deployed app directory). Never ~/.env — that holds deploy secrets.
        Env::load(dirname(__DIR__) . '/.env');

        $env = static fn (string $k): ?string => (($v = getenv($k)) === false || $v === '') ? null : $v;

        return new self(
            dataDir: $env('BDDPHP_DATA_DIR') ?? dirname(__DIR__) . '/data',
            defaultTtl: (int) ($env('BDDPHP_DEFAULT_TTL') ?? (string) Server::DEFAULT_TTL),
        );
    }

    public function store(): Store
    {
        return Store::fromDir($this->dataDir);
    }
}
