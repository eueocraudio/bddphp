#!/usr/bin/env bash
# Local development setup: install dev deps, create a .env, and run the tests.
#
#   ./install.sh                 # composer install + .env + selftest + phpunit
#   ./install.sh --no-test       # skip the test run
#   ./install.sh --no-dev        # production-style: no composer dev deps
set -euo pipefail

cd "$(dirname "$0")"

RUN_TEST=1
COMPOSER_FLAGS=()
for arg in "$@"; do
    case "$arg" in
        --no-test) RUN_TEST=0 ;;
        --no-dev)  COMPOSER_FLAGS+=(--no-dev) ;;
        --help|-h) sed -n '2,7p' "$0"; exit 0 ;;
        *) echo "unknown option: $arg" >&2; exit 1 ;;
    esac
done

# Required runtime: PHP 8.4 with the openssl, hash and curl extensions.
# Storage is a directory of files — no database extension needed.
php -r 'exit(PHP_VERSION_ID >= 80400 ? 0 : 1);' \
    || { echo "error: PHP >= 8.4 required (have $(php -r 'echo PHP_VERSION;'))" >&2; exit 1; }
for ext in openssl hash curl; do
    php -r "exit(extension_loaded('$ext') ? 0 : 1);" \
        || { echo "error: missing PHP extension: $ext" >&2; exit 1; }
done

if command -v composer >/dev/null; then
    composer install "${COMPOSER_FLAGS[@]}"
else
    echo "warning: composer not found — the app runs without it (manual autoloader)," >&2
    echo "         but PHPUnit is unavailable, so tests are limited to the selftest." >&2
fi

[[ -f .env ]] || { cp .env.example .env; echo "wrote .env (defaults are fine for local dev)"; }

# Crypto/protocol vectors — no storage needed.
php tests/selftest.php

if [[ "$RUN_TEST" == 1 && -x vendor/bin/phpunit ]]; then
    echo "running phpunit (uses throwaway temp directories; no database)..."
    vendor/bin/phpunit || echo "phpunit failed" >&2
fi

echo "done."
