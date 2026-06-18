# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`bddphp` is a PHP 8.4 port of the Python "Blind Dead Drop" (`../bdd`).
It is an HTTP service for exchanging messages through a server that **learns
nothing**: it stores opaque blobs at opaque addresses and can never read the
content, link a request to its response, or link the two parties. All crypto and
address derivation happen client-side. This blindness is the constraint that
drives every design decision.

Storage is a **directory of files** (one blob file per address) — no database.
This is a deliberate fit for the production host (shared hosting whose MySQL has
tight connection/query limits) and a return to the original's filesystem store.
A request that doesn't touch a slot touches no storage at all.

A second guiding constraint, inherited from the original: **lean on bundled,
audited primitives; add dependencies only with reason.** The crypto uses PHP's
own OpenSSL (`chacha20-poly1305`) and `hash_hkdf` — the PHP equivalent of the
original's choice of the audited `cryptography` library. There are *no* runtime
Composer dependencies; the app runs from a fresh checkout via `src/autoload.php`.
Composer/PHPUnit are dev-only.

## Reference docs

Three in-repo docs go deeper than this file; consult them before changing the
protocol or restating "why" decisions (all pt-BR):

- **`spec.md`** — the *normative* protocol spec: wire format, key/address
  derivation, HTTP API, byte-for-byte. The source of truth for interop with
  `../bdd`; change code and `spec.md` together.
- **`architecture.md`** — the code-organization rationale (the "why" behind the
  layering in this file's Architecture section).
- **`README.md`** + **`examples/README.md`** — project overview and the
  cross-language example clients. `docs/index.html` is the shipped doc site.

## Commands

```bash
./install.sh                  # check PHP/exts, composer install, write .env, run tests
bin/bdd migrate               # create the storage dir (./data) + its deny .htaccess
bin/bdd serve --port 8080     # dev server (PHP built-in server; HTTP only)
bin/bdd keygen                # print a fresh 32-byte hex root secret

php tests/selftest.php        # crypto/protocol RFC vectors only — no storage needed
composer test                 # full PHPUnit suite (no database; uses temp dirs)
vendor/bin/phpunit --filter testRequestResponseRoundTrip   # a single test
vendor/bin/phpunit --filter 'CryptoTest|StoreTest|ServerTest'  # skip integration

bash examples/demo.sh         # cross-language blind-RPC demo (local server)
php  examples/python/selftest.py        # from-scratch Python crypto vectors
( cd examples/cpp && make test )        # from-scratch C++ crypto vectors

BDD_REMOTE_DIR=. ./deploy.sh --dry-run  # stage the prod upload, send nothing
```

There is **no database**: `StoreTest`/`ServerTest`/`IntegrationTest` create
throwaway temp directories in `setUp` and remove them in `tearDown`, so the full
suite runs from a fresh checkout. The crypto/protocol work is also covered by the
standalone `selftest.php`. The server reads its data dir from `BDDPHP_DATA_DIR`
(default `./data` beside the code); tests point it at a temp dir.

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

- **`src/Store.php`** — `Store`, a filesystem-backed blob store: **one file per
  slot**, named by its address under a single data directory (`fromDir`/`init`).
  Address is validated as exactly 64 lowercase hex (`isValidAddress`), which both
  namespaces files and makes them safe path components (no traversal). Writes are
  **write-once**: `put()` refuses an occupied, unexpired address (returns false ⇒
  409) but transparently reuses an expired one; publishing is atomic (write a temp
  file carrying the expiry as its mtime, then `rename()` into place, so readers
  only ever see a complete blob). **Expiry is the file's mtime** (epoch seconds):
  enforced precisely on every read (expired ⇒ lazily `unlink`ed, read as absent)
  and via `sweep()`. `getBlocking()` is the long-poll primitive — no FS wakeup, so
  it polls at a fixed interval (each poll a local `stat`, not a DB round trip;
  `clearstatcache` keeps the poll honest within one request). Note: the only
  temporal metadata *written* is the bucketed expiry, but the inode's ctime still
  reflects real write time to anyone with filesystem access (a small blindness
  regression vs the old DB row, off the HTTP threat model).

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

- **`src/Config.php`** + **`src/Env.php`** — server/storage config. `Config::
  fromEnv()` loads a project-local `.env` (via `Env`, a tiny dotenv loader) and
  reads `BDDPHP_DATA_DIR` (default `./data`) and `BDDPHP_DEFAULT_TTL`. No
  database, so no credentials. It deliberately does **not** read `~/.env` (which
  holds only the deploy/FTP secrets).

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

The production target is **shared hosting** (Hostinger; FTP only — no database).
There is no long-running process — the host's web server runs `index.php`
per request; `.htaccess` (`DirectoryIndex index.html index.php`) serves the static
`docs/index.html` at `/`, routes `/v1/...` to the front controller, and denies
`src/`, `data/`, `.env`, etc. `deploy.sh` stages the web-root layout (front
controller + `.htaccess` + `index.html` + `src/` + the writable `data/` dir +
`.env` + `bddphp-examples.zip`) and mirrors it over FTP, reading credentials from
the `~/.env` "BDD PHP" section (`FTP_*_BDD`). **The mirror excludes `data/`** so a
deploy never wipes the live blobs; it only re-publishes `data/.htaccess`. Use
`./deploy.sh --dry-run` to inspect the staging tree first.

> **Host quirk:** the live `*.hostingersite.com` preview domain serves from the
> FTP **landing directory** (it contains `default.php`), not `public_html` — deploy
> with `BDD_REMOTE_DIR=. ./deploy.sh`. Live site:
> <https://darkgoldenrod-gnat-566022.hostingersite.com/>.

> The `data/` directory must be web-writable and **never web-servable** (the
> shipped `.htaccess` denies it). Deploy/FTP credentials live only in `~/.env` and
> must never be committed. Deploying is an outward-facing action — confirm with
> the user before running it.

## Invariants to preserve

- The server must stay blind: never log request bodies, peers, or anything
  linking the two parts/parties; never give the server the secret or any
  plaintext. New endpoints must keep addresses opaque and fixed-shape.
- Address space = 64 lowercase hex chars (SHA256 size). Anything reading a path
  must pass through `Store::isValidAddress` / the `/v1/slot/<64-hex>` route regex
  — this is also what makes an address safe as a filename (no `/`, no `..`).
- The blob directory (`data/`) must stay web-writable but **never web-servable**:
  serving a blob statically would bypass expiry and the front controller. The
  `data/.htaccess` deny rule and the web-root `.htaccess` `data/` block both guard
  this; keep them when changing deploy/routing.
- The wire format (`nonce(12) || tag(16) || ciphertext`) and the HKDF derivation
  labels are a cross-language contract. Changing either breaks interoperability
  with `../bdd` and its clients — the RFC-vector tests guard this.
