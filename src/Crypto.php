<?php

declare(strict_types=1);

namespace Bdd;

use RuntimeException;

/**
 * Thin wrappers over audited PHP primitives: ChaCha20-Poly1305 AEAD
 * (RFC 8439, via OpenSSL) and HKDF-SHA256 (RFC 5869, via ext-hash's
 * hash_hkdf). The original Python package leans on the audited `cryptography`
 * library for exactly these two operations; here we lean on the equivalent
 * primitives shipped with PHP.
 *
 * The wire format `nonce(12) || tag(16) || ciphertext` and the HKDF labels are
 * a cross-language contract: the Python/C++ reference clients reimplement them
 * independently. RFC test vectors in tests/ pin the byte layout, so do not let
 * it drift.
 */
final class Crypto
{
    public const NONCE_SIZE = 12;
    public const TAG_SIZE = 16;
    private const CIPHER = 'chacha20-poly1305';

    /**
     * HKDF-SHA256 with the RFC's default (all-zero) salt, matching the Python
     * package. PHP's hash_hkdf() uses a HashLen-zero salt when none is given,
     * which is RFC 5869 §2.2's "if not provided" case.
     */
    public static function hkdf(string $ikm, string $info, int $length): string
    {
        return hash_hkdf('sha256', $ikm, $length, $info, '');
    }

    /**
     * Seal plaintext under a 32-byte key. Returns nonce || tag || ciphertext.
     * AAD is empty in this protocol.
     */
    public static function seal(string $key, string $nonce, string $plaintext): string
    {
        $tag = '';
        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER,
            $key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            '',
            self::TAG_SIZE,
        );
        if ($ciphertext === false) {
            throw new RuntimeException('encryption failed: ' . openssl_error_string());
        }
        return $nonce . $tag . $ciphertext;
    }

    /**
     * Authenticate and decrypt a wire blob. Throws on tampering or truncation.
     */
    public static function open(string $key, string $blob): string
    {
        if (strlen($blob) < self::NONCE_SIZE + self::TAG_SIZE) {
            throw new RuntimeException('blob too short');
        }
        $nonce = substr($blob, 0, self::NONCE_SIZE);
        $tag = substr($blob, self::NONCE_SIZE, self::TAG_SIZE);
        $ciphertext = substr($blob, self::NONCE_SIZE + self::TAG_SIZE);
        $plaintext = openssl_decrypt(
            $ciphertext,
            self::CIPHER,
            $key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            '',
        );
        if ($plaintext === false) {
            throw new RuntimeException('authentication failed');
        }
        return $plaintext;
    }
}
