<?php

declare(strict_types=1);

namespace Bdd\Tests;

use Bdd\Crypto;
use Bdd\Protocol;
use PHPUnit\Framework\TestCase;

/**
 * RFC vectors and round-trips for the audited primitives. These pin the wire
 * byte layout the reference clients in other languages reimplement, so keep
 * them green.
 */
final class CryptoTest extends TestCase
{
    public function testHkdfRfc5869Case3(): void
    {
        $okm = Crypto::hkdf(str_repeat("\x0b", 22), '', 42);
        self::assertSame(
            '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d'
            . '9d201395faa4b61a96c8',
            bin2hex($okm),
        );
    }

    public function testAeadCiphertextMatchesRfc8439(): void
    {
        $key = (string) hex2bin('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');
        $nonce = (string) hex2bin('070000004041424344454647');
        $pt = "Ladies and Gentlemen of the class of '99: If I could offer you "
            . "only one tip for the future, sunscreen would be it.";
        $blob = Crypto::seal($key, $nonce, $pt);
        $ct = substr($blob, Crypto::NONCE_SIZE + Crypto::TAG_SIZE);
        self::assertSame('d31a8d34648e60db7b86afbc53ef7ec2', bin2hex(substr($ct, 0, 16)));
    }

    public function testWireLayoutIsNonceTagCiphertext(): void
    {
        $key = random_bytes(32);
        $nonce = random_bytes(Crypto::NONCE_SIZE);
        $blob = Crypto::seal($key, $nonce, 'hello');
        self::assertSame($nonce, substr($blob, 0, Crypto::NONCE_SIZE));
        self::assertSame(Crypto::NONCE_SIZE + Crypto::TAG_SIZE + 5, strlen($blob));
    }

    public function testRoundTrip(): void
    {
        $key = random_bytes(32);
        $nonce = random_bytes(Crypto::NONCE_SIZE);
        $blob = Crypto::seal($key, $nonce, 'deadbeef payload');
        self::assertSame('deadbeef payload', Crypto::open($key, $blob));
    }

    public function testTamperIsDetected(): void
    {
        $key = random_bytes(32);
        $blob = Crypto::seal($key, random_bytes(Crypto::NONCE_SIZE), 'secret');
        $blob[28] = $blob[28] ^ "\x01";
        $this->expectException(\RuntimeException::class);
        Crypto::open($key, $blob);
    }

    public function testRequestAndResponseDeriveUnrelatedAddresses(): void
    {
        $secret = str_repeat("\x42", 32);
        $req = Protocol::slotAddress($secret, Protocol::REQUEST, 0);
        $res = Protocol::slotAddress($secret, Protocol::RESPONSE, 0);
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $req);
        self::assertNotSame($req, $res);
        // Different channels also diverge.
        self::assertNotSame($req, Protocol::slotAddress($secret, Protocol::REQUEST, 1));
    }

    public function testSealOpenViaProtocol(): void
    {
        $secret = random_bytes(Protocol::SECRET_SIZE);
        $blob = Protocol::seal($secret, Protocol::REQUEST, 7, 'ping?');
        self::assertSame('ping?', Protocol::open($secret, Protocol::REQUEST, 7, $blob));
    }
}
