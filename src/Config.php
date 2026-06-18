<?php

declare(strict_types=1);

namespace Bdd;

/**
 * Server configuration read from the environment, so secrets (DB password)
 * never live in code or argv. Used by the front controller and the CLI `serve`.
 *
 * Two naming schemes are accepted, BDDPHP_* taking precedence:
 *
 *   BDDPHP_DSN         full PDO DSN (default mysql:host=127.0.0.1;dbname=bddphp)
 *   BDDPHP_DB_USER     database user (default bddphp)
 *   BDDPHP_DB_PASS     database password (default empty)
 *   BDDPHP_DEFAULT_TTL default entry lifetime in seconds, snapped to a bucket
 *
 * or the production "_BDD" scheme shared with the deploy tooling and ~/.env:
 *
 *   MYSQL_HOST_BDD / MYSQL_DATA_BDD / MYSQL_USER_BDD / MYSQL_PASS_BDD
 *
 * fromEnv() first loads a local `.env` (next to the deployed code) via Env, so
 * a shared host that can't set real env vars still gets configured. It does NOT
 * read ~/.env — that file holds production credentials and is consumed only by
 * the deploy script, so a local `serve` never accidentally targets production.
 */
final class Config
{
    public function __construct(
        public readonly string $dsn,
        public readonly string $dbUser,
        public readonly string $dbPass,
        public readonly int $defaultTtl,
    ) {
    }

    public static function fromEnv(): self
    {
        // Load a `.env` sitting next to the code (project root in dev, or the
        // deployed app directory). Never ~/.env — that holds production secrets.
        Env::load(dirname(__DIR__) . '/.env');

        $env = static fn (string $k): ?string => (($v = getenv($k)) === false || $v === '') ? null : $v;

        // Prefer an explicit DSN; otherwise assemble one from the _BDD pieces.
        $dsn = $env('BDDPHP_DSN');
        if ($dsn === null) {
            $host = $env('MYSQL_HOST_BDD') ?? '127.0.0.1';
            $db = $env('MYSQL_DATA_BDD') ?? 'bddphp';
            $charset = $env('BDDPHP_DB_CHARSET') ?? 'utf8mb4';
            $dsn = "mysql:host=$host;dbname=$db;charset=$charset";
        }

        return new self(
            dsn: $dsn,
            dbUser: $env('BDDPHP_DB_USER') ?? $env('MYSQL_USER_BDD') ?? 'bddphp',
            dbPass: $env('BDDPHP_DB_PASS') ?? $env('MYSQL_PASS_BDD') ?? '',
            defaultTtl: (int) ($env('BDDPHP_DEFAULT_TTL') ?? (string) Server::DEFAULT_TTL),
        );
    }

    public function store(): Store
    {
        return Store::fromDsn($this->dsn, $this->dbUser, $this->dbPass);
    }
}
