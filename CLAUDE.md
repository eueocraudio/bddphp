# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`bddphp` is a PHP 8.4 + MySQL port of the Python "Blind Dead Drop" (`../bdd`).
It is an HTTP service for exchanging messages through a server that **learns
nothing**: it stores opaque blobs at opaque addresses and can never read the
content, link a request to its response, or link the two parties. All crypto and
address derivation happen client-side. This blindness is the constraint that
drives every design decision.

A second guiding constraint, inherited from the original: **lean on bundled,
audited primitives; add dependencies only with reason.** The crypto uses PHP's
own OpenSSL (`chacha20-poly1305`) and `hash_hkdf` — the PHP equivalent of the
original's choice of the audited `cryptography` library. There are *no* runtime
Composer dependencies; the app runs from a fresh checkout via `src/autoload.php`.
Composer/PHPUnit are dev-only.

## Commands

```bash
./install.sh                  # check PHP/exts, composer install, write .env, run tests
bin/bdd migrate               # create the slots table (CREATE TABLE IF NOT EXISTS)
bin/bdd serve --port 8080     # dev server (PHP built-in server; HTTP only)
bin/bdd keygen                # print a fresh 32-byte hex root secret

php tests/selftest.php        # crypto/protocol RFC vectors only — no DB needed
composer test                 # full PHPUnit suite (needs a reachable test DB)
vendor/bin/phpunit --filter testRequestResponseRoundTrip   # a single test
vendor/bin/phpunit --filter 'CryptoTest|StoreTest|ServerTest'  # skip integration

bash examples/demo.sh         # cross-language blind-RPC demo (needs a local DB)
php  examples/python/selftest.py        # from-scratch Python crypto vectors
( cd examples/cpp && make test )        # from-scratch C++ crypto vectors

BDD_REMOTE_DIR=. ./deploy.sh --dry-run  # stage the prod upload, send nothing
```

Tests requiring a database read `BDDPHP_TEST_*` from `phpunit.xml` (default DB
`bddphp_test` on `127.0.0.1`, user/pass `bddphp`). `StoreTest`/`ServerTest`/
`IntegrationTest` self-skip if `BDDPHP_TEST_DSN` is unset. The crypto/protocol
work has no DB dependency and is also covered by the standalone `selftest.php`.

## Architecture

Data flows client → server; the trust boundary is the client: only it ever holds
the root secret or sees plaintext.

- **`src/Crypto.php`** — thin wrappers over OpenSSL (`seal`/`open`, ChaCha20-
  Poly1305) and `hash_hkdf` (`hkdf`). The wire format `nonce(12) || tag(16) ||
  ciphertext` and the HKDF labels are a **cross-language contract** pinned by RFC
  vectors in `tests/CryptoTest.php` and `tests/selftest.php` — keep them green so
  the byte layout the other-language clients depend on cannot drift. AAD is empty
  (so the AEAD tag differs from RFC vectors that authenticate AAD; the ciphertext
  still matches and we pin the empty-AAD tag).

- **`src/Protocol.php`** — the shared client-side rules that make the drop blind.
  A channel (int) holds two `PARTS`: `request` and `response`. Both the slot
  **address** and the message **key** are `HKDF(secret, "bdd-{addr,key}|<part>|
  <channel>")`. Different labels ⇒ unrelated addresses under unrelated keys ⇒ the
  server cannot link them. `seal`/`open` define the wire blob.

- **`src/Store.php`** — `Store`, a MySQL-backed blob store (PDO), the main change
  from the filesystem original. One table `slots(address, payload, expires_at)`;
  address is validated as exactly 64 lowercase hex (`isValidAddress`), which both
  namespaces rows and makes them safe parameters. Writes are **write-once**:
  `put()` refuses an occupied, unexpired address (returns false ⇒ 409) but
  transparently reuses an expired one, guarded by a `SELECT ... FOR UPDATE`
  transaction. **Expiry is the `expires_at` column** (epoch seconds): enforced
  precisely on every read (expired ⇒ lazily deleted, read as absent) and via
  `sweep()`. `getBlocking()` is the long-poll primitive — MySQL has no cross-
  connection wakeup here, so it polls at a fixed interval until the deadline.

- **`src/Server.php`** + **`src/Responder.php`** — front-controller request
  handling, independent of the HTTP context so it is unit-testable: `Server::
  handle($method,$path,$query,$body,$responder)` returns the status code.
  `Responder` in capture mode records the response for tests; in normal mode it
  emits it while stripping `X-Powered-By` (blindness at the header level — note
  `Server`/`Date` from the fronting web server must be quieted there). Routes
  match `/v1/slot/<64-hex>`; `?wait=N` long-polls via `getBlocking` (capped at
  `MAX_WAIT`=60s); `?ttl=N` is snapped up to a `TTL_BUCKETS` value; bodies are
  capped at `MAX_BLOB`=1 MiB. `GET /` returns a minimal inline landing page
  (fallback for when the static `docs/index.html` is not present at the web root).

- **`public/index.php`** — the front controller. Works as a router for the PHP
  built-in server (`php -S ... public/index.php`) and as the web-root entry under
  Apache/LiteSpeed. It locates `autoload.php` whether it lives in the dev
  `public/` subdir or at the deployed web root.

- **`src/Client.php`** — `Client` over the curl extension: `send`/`receive(part,
  channel,wait)`/`waitReceive`/`purge`. The only component holding the secret.
  Supports `http`/`https` with `--insecure`/`--cafile`.

- **`src/Cli.php`** + **`bin/bdd`** — subcommands `serve`, `migrate`, `keygen`,
  `send`, `recv`. The root secret comes from `--secret` or `BDD_SECRET`. `serve`
  spawns `php -S` with `PHP_CLI_SERVER_WORKERS` so a held long-poll doesn't
  starve other requests.

- **`src/Config.php`** + **`src/Env.php`** — server/DB config. `Config::fromEnv()`
  loads a project-local `.env` (via `Env`, a tiny dotenv loader) and accepts
  either `BDDPHP_*` or the production `MYSQL_*_BDD` scheme. It deliberately does
  **not** read `~/.env`, so a local `serve` can never accidentally hit production.

- **`examples/`** — interoperable clients in PHP (native, imports the package),
  Python and C++ (from-scratch crypto, proving the wire format is a cross-language
  contract). All accept the same commands (`send-request`/`get-request`/
  `send-response`/`get-response`/`wait-response`/`reply-upper`) plus `--scheme
  http|https`. `examples/demo.sh` runs three cross-language blind RPCs. The Python
  and C++ selftests pin the from-scratch crypto against the RFC vectors.

- **`docs/index.html`** — a single-file documentation site (pt-BR) with the API
  reference and an in-browser WebCrypto address deriver that self-checks against a
  known vector (byte-identical to the server). Deployed as the web-root landing
  page. `bddphp-examples.zip` (generated by `deploy.sh`) is the downloadable,
  self-contained bundle linked from it.

## Deployment

The production target is **shared hosting** (Hostinger; FTP + a remote MySQL).
There is no long-running process — the host's web server runs `index.php`
per request; `.htaccess` (`DirectoryIndex index.html index.php`) serves the static
`docs/index.html` at `/`, routes `/v1/...` to the front controller, and denies
`src/`, `.env`, etc. `deploy.sh` stages the web-root layout (front controller +
`.htaccess` + `index.html` + `src/` + a generated `.env` + `bddphp-examples.zip`)
and mirrors it over FTP, reading credentials from the `~/.env` "BDD PHP" section
(`FTP_*_BDD`, `MYSQL_*_BDD`). It generates the deployed `.env` and keeps secrets
out of git. Use `./deploy.sh --dry-run` to inspect the staging tree first.

> **Host quirk:** the live `*.hostingersite.com` preview domain serves from the
> FTP **landing directory** (it contains `default.php`), not `public_html` — deploy
> with `BDD_REMOTE_DIR=. ./deploy.sh`. Live site:
> <https://darkgoldenrod-gnat-566022.hostingersite.com/>.

> Production credentials live only in `~/.env` and must never be committed.
> Deploying and migrating the production DB are outward-facing actions — confirm
> with the user before running them.

## Invariants to preserve

- The server must stay blind: never log request bodies, peers, or anything
  linking the two parts/parties; never give the server the secret or any
  plaintext. New endpoints must keep addresses opaque and fixed-shape.
- Address space = 64 lowercase hex chars (SHA256 size). Anything reading a path
  must pass through `Store::isValidAddress` / the `/v1/slot/<64-hex>` route regex.
- The wire format (`nonce(12) || tag(16) || ciphertext`) and the HKDF derivation
  labels are a cross-language contract. Changing either breaks interoperability
  with `../bdd` and its clients — the RFC-vector tests guard this.
