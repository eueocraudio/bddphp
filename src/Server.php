<?php

declare(strict_types=1);

namespace Bdd;

/**
 * Blind HTTP dead-drop server (front-controller style; works under the PHP
 * built-in server or php-fpm + nginx).
 *
 * Endpoints (all addresses are 64-char hex):
 *
 *   GET    /v1/health                       -> {"status":"ok","ttl_buckets":[...]}
 *   PUT    /v1/slot/<address>[?ttl=N]  body  -> 201 created / 409 occupied
 *   GET    /v1/slot/<address>[?wait=N]       -> 200 blob / 404
 *   DELETE /v1/slot/<address>                -> 204 / 404
 *
 * The server stores opaque blobs at opaque addresses. It logs nothing about
 * request contents or peers, and never links a request to its response or the
 * two parties — every byte it sees (address and blob) is opaque.
 *
 * Unlike the Python server there is no built-in TLS: the PHP built-in server
 * cannot wrap TLS, so transport security is expected from the fronting layer (a
 * Tor onion service or a reverse proxy). Message content is already end-to-end
 * encrypted by the client, so plain HTTP between proxy and app is the intended
 * deployment — the same role the Python server's `--no-tls` mode played.
 */
final class Server
{
    public const MAX_BLOB = 1 << 20;   // 1 MiB ceiling per slot
    public const MAX_WAIT = 60.0;      // cap on long-poll hold time, seconds

    // Standardized expiry buckets (seconds): 5 min, 1 hour, 1 day, 1 week.
    public const TTL_BUCKETS = [300, 3600, 86400, 604800];
    public const DEFAULT_TTL = 86400;

    private readonly int $defaultTtl;

    public function __construct(
        private readonly Store $store,
        int $defaultTtl = self::DEFAULT_TTL,
    ) {
        $this->defaultTtl = self::snapTtl($defaultTtl);
    }

    /** Round a requested lifetime up to the nearest allowed bucket (capped). */
    public static function snapTtl(int $requested): int
    {
        foreach (self::TTL_BUCKETS as $bucket) {
            if ($requested <= $bucket) {
                return $bucket;
            }
        }
        return self::TTL_BUCKETS[array_key_last(self::TTL_BUCKETS)];
    }

    /**
     * A static human-facing landing page for `GET /` so a browser visit shows
     * the service is up and documents the API. It reveals nothing sensitive
     * (the same public endpoint list as the README) and pulls in no external
     * resources, preserving the server's blindness.
     */
    private static function landingPage(): string
    {
        $buckets = implode(', ', self::TTL_BUCKETS);
        return <<<HTML
            <!doctype html>
            <html lang="pt-BR">
            <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <meta name="robots" content="noindex">
            <title>bddphp — Blind Dead Drop</title>
            <style>
              :root { color-scheme: light dark; }
              body { font: 16px/1.6 system-ui, sans-serif; max-width: 46rem;
                     margin: 3rem auto; padding: 0 1.2rem; }
              code, pre { font-family: ui-monospace, monospace; }
              pre { background: rgba(127,127,127,.12); padding: 1rem;
                    border-radius: 8px; overflow-x: auto; }
              h1 { margin-bottom: .2rem; }
              .tag { display:inline-block; padding:.1rem .5rem; border-radius:6px;
                     background:#16a34a; color:#fff; font-size:.8rem; }
              a { color: #2563eb; }
            </style>
            </head>
            <body>
            <h1>bddphp <span class="tag">online</span></h1>
            <p><strong>Blind Dead Drop</strong> — duas partes trocam mensagens por um
            servidor que não aprende nada: ele guarda blobs opacos em endereços
            opacos e nunca lê o conteúdo, liga request a response, nem liga as duas
            partes. Toda a criptografia acontece no cliente.</p>

            <h2>API</h2>
            <pre>GET    /v1/health
            PUT    /v1/slot/&lt;address&gt;[?ttl=N]   corpo: blob -&gt; 201 / 409 (write-once)
            GET    /v1/slot/&lt;address&gt;[?wait=N]              -&gt; 200 blob / 404
            DELETE /v1/slot/&lt;address&gt;                       -&gt; 204 / 404</pre>
            <p><code>&lt;address&gt;</code> = 64 hex; corpo até 1 MiB; expiração em
            buckets de $buckets s. Veja <a href="/v1/health">/v1/health</a>.</p>

            <p>Esta página é só informativa — o serviço é uma API. Use um cliente
            bddphp (CLI <code>bin/bdd</code> ou os exemplos em PHP/Python/C++).</p>
            </body>
            </html>
            HTML;
    }

    /**
     * Handle a single request described by ($method, $path, $query, $body) and
     * emit the response via the provided sink (defaults to real PHP output).
     * Returns the HTTP status code (handy for tests).
     */
    public function handle(
        string $method,
        string $path,
        array $query,
        string $body,
        ?Responder $out = null,
    ): int {
        $out ??= new Responder();

        if ($method === 'GET' && ($path === '/' || $path === '/index.php')) {
            return $out->send(200, self::landingPage(), 'text/html; charset=utf-8');
        }

        if ($method === 'GET' && $path === '/v1/health') {
            $payload = json_encode([
                'status' => 'ok',
                'ttl_buckets' => self::TTL_BUCKETS,
            ]);
            return $out->send(200, $payload, 'application/json');
        }

        $addr = self::slotAddress($path);
        if ($addr === null) {
            return $out->send(404);
        }

        return match ($method) {
            'GET' => $this->doGet($addr, $query, $out),
            'PUT' => $this->doPut($addr, $query, $body, $out),
            'DELETE' => $out->send($this->store->delete($addr) ? 204 : 404),
            default => $out->send(404),
        };
    }

    private function doGet(string $addr, array $query, Responder $out): int
    {
        $wait = $this->waitSeconds($query);
        $blob = $wait > 0
            ? $this->store->getBlocking($addr, $wait)
            : $this->store->get($addr);
        if ($blob === null) {
            return $out->send(404);
        }
        return $out->send(200, $blob);
    }

    private function doPut(string $addr, array $query, string $body, Responder $out): int
    {
        $length = strlen($body);
        if ($length <= 0 || $length > self::MAX_BLOB) {
            return $out->send(413);
        }
        $ttl = $this->ttlSeconds($query);
        $created = $this->store->put($addr, $body, time() + $ttl);
        return $out->send($created ? 201 : 409);
    }

    private static function slotAddress(string $path): ?string
    {
        if (preg_match('#^/v1/slot/([0-9a-f]{64})$#', $path, $m) === 1) {
            return $m[1];
        }
        return null;
    }

    /** Parse and clamp the ?wait=N long-poll parameter. */
    private function waitSeconds(array $query): float
    {
        $raw = $query['wait'] ?? '0';
        if (!is_numeric($raw)) {
            return 0.0;
        }
        return max(0.0, min((float) $raw, self::MAX_WAIT));
    }

    /** Parse ?ttl=N and snap it to a bucket; default if absent/invalid. */
    private function ttlSeconds(array $query): int
    {
        $raw = $query['ttl'] ?? null;
        if ($raw === null || !is_numeric($raw)) {
            return $this->defaultTtl;
        }
        return self::snapTtl(max(1, (int) $raw));
    }
}
