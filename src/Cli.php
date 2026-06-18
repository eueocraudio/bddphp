<?php

declare(strict_types=1);

namespace Bdd;

/**
 * Command-line interface for bddphp.
 *
 *   bdd serve   [--host H] [--port N] [--ttl S]
 *   bdd migrate                         # create the storage directory
 *   bdd keygen                          # print a fresh 32-byte hex secret
 *   bdd send    --part P --channel N [--message M | --file F] [--ttl S]
 *   bdd recv    --part P --channel N [--wait] [--timeout S] [--purge]
 *
 * The root secret comes from --secret or the BDD_SECRET environment variable.
 * Server/storage settings come from the BDDPHP_* environment variables (Config).
 */
final class Cli
{
    public function __construct(private readonly array $argv)
    {
    }

    public function run(): int
    {
        $args = $this->argv;
        array_shift($args); // program name
        $command = array_shift($args) ?? '';

        return match ($command) {
            'serve' => $this->serve($this->parseFlags($args)),
            'migrate' => $this->migrate(),
            'keygen' => $this->keygen(),
            'send' => $this->send($this->parseFlags($args)),
            'recv' => $this->recv($this->parseFlags($args)),
            '', '-h', '--help', 'help' => $this->usage(),
            default => $this->fail("unknown command: $command\n" . self::USAGE),
        };
    }

    private const USAGE = <<<TXT
        usage: bdd <command> [options]

          serve   [--host H] [--port N] [--ttl S]   run the blind HTTP server
          migrate                                   create the storage directory
          keygen                                    print a fresh root secret
          send    --part request|response --channel N [--message M | --file F] [--ttl S]
          recv    --part request|response --channel N [--wait] [--timeout S] [--purge]

        send/recv client options:
          --secret HEX   32-byte hex root secret (or env BDD_SECRET)
          --host H       server host (default 127.0.0.1)
          --port N       server port (default 8080)
          --scheme S     http or https (default http)
          --insecure     skip TLS verification (https only; dev/self-signed)
          --cafile PATH  CA bundle to verify the server cert (https)

        ttl buckets (s): 300, 3600, 86400, 604800
        TXT;

    private function usage(): int
    {
        fwrite(STDOUT, self::USAGE . "\n");
        return 0;
    }

    private function serve(array $f): int
    {
        $config = Config::fromEnv();
        $host = $f['host'] ?? '127.0.0.1';
        $port = (int) ($f['port'] ?? 8080);
        if (isset($f['ttl'])) {
            putenv('BDDPHP_DEFAULT_TTL=' . (int) $f['ttl']);
        }
        // The built-in server is single-threaded; long-poll would block other
        // requests. Spawn worker processes so concurrent holds don't starve.
        if (getenv('PHP_CLI_SERVER_WORKERS') === false) {
            putenv('PHP_CLI_SERVER_WORKERS=8');
        }
        $router = dirname(__DIR__) . '/public/index.php';
        fwrite(STDERR, "bdd serving on http://$host:$port (router=$router)\n");
        fwrite(STDERR, "note: no TLS — front with a reverse proxy or Tor onion service\n");
        $cmd = sprintf('exec php -S %s:%d %s', escapeshellarg($host), $port, escapeshellarg($router));
        passthru($cmd, $code);
        return $code;
    }

    private function migrate(): int
    {
        Config::fromEnv()->store()->init();
        fwrite(STDERR, "storage ready\n");
        return 0;
    }

    private function keygen(): int
    {
        fwrite(STDOUT, bin2hex(random_bytes(Protocol::SECRET_SIZE)) . "\n");
        return 0;
    }

    private function send(array $f): int
    {
        $client = $this->client($f);
        $part = $this->requirePart($f);
        $channel = $this->requireChannel($f);

        if (isset($f['file'])) {
            $payload = (string) file_get_contents($f['file']);
        } elseif (isset($f['message'])) {
            $payload = (string) $f['message'];
        } else {
            $payload = (string) stream_get_contents(STDIN);
        }

        $ttl = isset($f['ttl']) ? (int) $f['ttl'] : null;
        $status = $client->send($part, $channel, $payload, $ttl);
        return match ($status) {
            201 => $this->ok('stored'),
            409 => $this->fail('slot already used', 2),
            default => $this->fail("server returned $status"),
        };
    }

    private function recv(array $f): int
    {
        $client = $this->client($f);
        $part = $this->requirePart($f);
        $channel = $this->requireChannel($f);

        if (isset($f['wait'])) {
            $interval = isset($f['interval']) ? (float) $f['interval'] : 25.0;
            $timeout = isset($f['timeout']) ? (float) $f['timeout'] : null;
            $plaintext = $client->waitReceive($part, $channel, $interval, $timeout);
        } else {
            $plaintext = $client->receive($part, $channel);
        }

        if ($plaintext === null) {
            $msg = isset($f['wait']) ? 'timed out waiting' : 'no message at that slot';
            return $this->fail($msg, 2);
        }
        fwrite(STDOUT, $plaintext);
        if (isset($f['purge'])) {
            $client->purge($part, $channel);
        }
        return 0;
    }

    private function client(array $f): Client
    {
        return new Client(
            secret: $this->loadSecret($f),
            host: $f['host'] ?? '127.0.0.1',
            port: (int) ($f['port'] ?? 8080),
            scheme: $f['scheme'] ?? 'http',
            insecure: isset($f['insecure']),
            cafile: $f['cafile'] ?? '',
        );
    }

    private function loadSecret(array $f): string
    {
        $hex = $f['secret'] ?? (getenv('BDD_SECRET') ?: '');
        if ($hex === '') {
            $this->fail('provide --secret or set BDD_SECRET');
            exit(1);
        }
        $secret = @hex2bin($hex);
        if ($secret === false || strlen($secret) !== Protocol::SECRET_SIZE) {
            $this->fail('secret must be ' . Protocol::SECRET_SIZE . ' bytes (' . (Protocol::SECRET_SIZE * 2) . ' hex chars)');
            exit(1);
        }
        return $secret;
    }

    private function requirePart(array $f): string
    {
        $part = $f['part'] ?? '';
        if (!in_array($part, Protocol::PARTS, true)) {
            $this->fail('--part must be one of: ' . implode(', ', Protocol::PARTS));
            exit(1);
        }
        return $part;
    }

    private function requireChannel(array $f): int
    {
        if (!isset($f['channel']) || !is_numeric($f['channel'])) {
            $this->fail('--channel N is required');
            exit(1);
        }
        return (int) $f['channel'];
    }

    /**
     * Parse `--flag value` and boolean `--flag` arguments into a map.
     * A flag followed by another flag (or nothing) is treated as a boolean.
     */
    private function parseFlags(array $args): array
    {
        $flags = [];
        for ($i = 0, $n = count($args); $i < $n; $i++) {
            $arg = $args[$i];
            if (!str_starts_with($arg, '--')) {
                continue;
            }
            $key = substr($arg, 2);
            $next = $args[$i + 1] ?? null;
            if ($next === null || str_starts_with($next, '--')) {
                $flags[$key] = true;
            } else {
                $flags[$key] = $next;
                $i++;
            }
        }
        return $flags;
    }

    private function ok(string $msg): int
    {
        fwrite(STDERR, "ok: $msg\n");
        return 0;
    }

    private function fail(string $msg, int $code = 1): int
    {
        fwrite(STDERR, "error: $msg\n");
        return $code;
    }
}
