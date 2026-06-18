<?php

declare(strict_types=1);

namespace Bdd;

use InvalidArgumentException;
use RuntimeException;

/**
 * Dead-drop client: derives slots/keys, encrypts, and talks to the server over
 * the curl extension. The client is the only component that holds the root
 * secret and sees plaintext.
 */
final class Client
{
    public function __construct(
        private readonly string $secret,
        private readonly string $host = '127.0.0.1',
        private readonly int $port = 8080,
        private readonly string $scheme = 'http',
        private readonly bool $insecure = false,
        private readonly string $cafile = '',
    ) {
        if (strlen($secret) !== Protocol::SECRET_SIZE) {
            throw new InvalidArgumentException('secret must be 32 bytes');
        }
    }

    /**
     * Seal $plaintext and PUT it at a channel part. $ttl (seconds) is rounded
     * up to a server bucket; omit (null) to use the server default. Returns the
     * HTTP status (201 created, 409 already used).
     */
    public function send(string $part, int $channel, string $plaintext, ?int $ttl = null): int
    {
        $blob = Protocol::seal($this->secret, $part, $channel, $plaintext);
        $addr = Protocol::slotAddress($this->secret, $part, $channel);
        $path = "/v1/slot/$addr";
        if ($ttl !== null) {
            $path .= '?ttl=' . $ttl;
        }
        [$status] = $this->request('PUT', $path, $blob, 30);
        return $status;
    }

    /**
     * Fetch and decrypt a channel part, or null if absent. If $wait > 0, ask
     * the server to long-poll: hold the request until a message appears or
     * $wait seconds elapse (the server caps this).
     */
    public function receive(string $part, int $channel, float $wait = 0): ?string
    {
        $addr = Protocol::slotAddress($this->secret, $part, $channel);
        $path = "/v1/slot/$addr";
        $maxtime = 30;
        if ($wait > 0) {
            $path .= '?wait=' . $wait;
            $maxtime = (int) ($wait + 10); // socket timeout must outlast the hold
        }
        [$status, $body] = $this->request('GET', $path, null, $maxtime);
        if ($status !== 200) {
            return null;
        }
        return Protocol::open($this->secret, $part, $channel, $body);
    }

    /**
     * Block until a message appears at the slot, then decrypt and return it.
     * Each request holds for up to $interval seconds (kept under the server
     * cap), re-issued until the overall $timeout (null = wait forever). Returns
     * null on timeout.
     */
    public function waitReceive(string $part, int $channel, float $interval = 25.0, ?float $timeout = null): ?string
    {
        $deadline = $timeout === null ? null : microtime(true) + $timeout;
        do {
            $hold = $interval;
            if ($deadline !== null) {
                $hold = min($hold, $deadline - microtime(true));
                if ($hold <= 0) {
                    return null;
                }
            }
            $plaintext = $this->receive($part, $channel, $hold);
            if ($plaintext !== null) {
                return $plaintext;
            }
        } while ($deadline === null || microtime(true) < $deadline);
        return null;
    }

    /** Delete a channel part after reading. Returns true if it existed. */
    public function purge(string $part, int $channel): bool
    {
        $addr = Protocol::slotAddress($this->secret, $part, $channel);
        [$status] = $this->request('DELETE', "/v1/slot/$addr", null, 30);
        return $status === 204;
    }

    /** @return array{0:int,1:string} [status, body] */
    private function request(string $method, string $path, ?string $body, int $maxtime): array
    {
        $url = "{$this->scheme}://{$this->host}:{$this->port}{$path}";
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, $maxtime);
        if ($this->scheme === 'https') {
            if ($this->insecure) {
                curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
                curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
            } elseif ($this->cafile !== '') {
                curl_setopt($ch, CURLOPT_CAINFO, $this->cafile);
            }
        }
        if ($body !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
            curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/octet-stream']);
        }
        $out = curl_exec($ch);
        if ($out === false) {
            $err = curl_error($ch);
            curl_close($ch);
            throw new RuntimeException("curl: $err");
        }
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);
        return [$status, (string) $out];
    }
}
