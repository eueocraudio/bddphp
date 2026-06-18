<?php

declare(strict_types=1);

namespace Bdd;

use InvalidArgumentException;

/**
 * Shared client-side protocol: how addresses, keys and blobs are derived.
 *
 * Two parties share a 32-byte root secret out of band. A logical slot is a
 * *channel* (an integer index) holding two independent payloads, or *parts*:
 * "request" and "response". From the secret we deterministically derive, per
 * channel and per part:
 *
 *   - a slot address = HKDF(secret, "bdd-addr|<part>|<channel>") -> hex
 *   - a message key  = HKDF(secret, "bdd-key|<part>|<channel>")
 *
 * Because request and response use different info labels, they live at
 * unrelated-looking addresses under unrelated keys. The server only ever sees
 * those addresses and the encrypted blobs, so it cannot read content, cannot
 * link request to response, and cannot link the two parties.
 *
 * Wire blob layout: nonce(12) || tag(16) || ciphertext.
 */
final class Protocol
{
    public const SECRET_SIZE = 32;

    public const REQUEST = 'request';
    public const RESPONSE = 'response';
    public const PARTS = [self::REQUEST, self::RESPONSE];

    private static function checkPart(string $part): void
    {
        if (!in_array($part, self::PARTS, true)) {
            throw new InvalidArgumentException(
                "part must be one of: " . implode(', ', self::PARTS) . ", got '$part'"
            );
        }
    }

    private static function info(string $kind, string $part, int $channel): string
    {
        return "bdd-$kind|$part|$channel";
    }

    public static function slotAddress(string $secret, string $part, int $channel): string
    {
        self::checkPart($part);
        return bin2hex(Crypto::hkdf($secret, self::info('addr', $part, $channel), 32));
    }

    public static function messageKey(string $secret, string $part, int $channel): string
    {
        self::checkPart($part);
        return Crypto::hkdf($secret, self::info('key', $part, $channel), 32);
    }

    /** Encrypt plaintext into a wire blob for the given channel part. */
    public static function seal(string $secret, string $part, int $channel, string $plaintext): string
    {
        $key = self::messageKey($secret, $part, $channel);
        $nonce = random_bytes(Crypto::NONCE_SIZE);
        return Crypto::seal($key, $nonce, $plaintext);
    }

    /** Decrypt and authenticate a wire blob. Throws on tampering. */
    public static function open(string $secret, string $part, int $channel, string $blob): string
    {
        $key = self::messageKey($secret, $part, $channel);
        return Crypto::open($key, $blob);
    }
}
