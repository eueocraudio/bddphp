<?php

declare(strict_types=1);

/**
 * Standalone crypto vector check — no Composer, no storage required.
 *   php tests/selftest.php
 *
 * Pins the HKDF-SHA256 and ChaCha20-Poly1305 byte layout against RFC vectors,
 * so the wire format the (Python/C++) reference clients depend on cannot drift.
 */

require __DIR__ . '/../src/autoload.php';

use Bdd\Crypto;
use Bdd\Protocol;

$failures = 0;
function check(string $name, string $got, string $want): void
{
    global $failures;
    if ($got === $want) {
        printf("ok    %s\n", $name);
    } else {
        printf("FAIL  %s\n        got  %s\n        want %s\n", $name, $got, $want);
        $failures++;
    }
}

// HKDF-SHA256 (RFC 5869 case 3: zero salt, empty info, L=42).
check(
    'hkdf rfc5869#3',
    bin2hex(Crypto::hkdf(str_repeat("\x0b", 22), '', 42)),
    '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d'
    . '9d201395faa4b61a96c8'
);

// ChaCha20-Poly1305 AEAD: ciphertext matches the RFC 8439 §2.8.2 known answer
// (the keystream is independent of AAD). This protocol uses empty AAD, so the
// tag differs from the RFC's (which authenticated 12 bytes of AAD); we pin the
// empty-AAD tag, which is the actual cross-language wire contract here.
$key = hex2bin('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');
$nonce = hex2bin('070000004041424344454647');
$pt = 'Ladies and Gentlemen of the class of \'99: If I could offer you only '
    . 'one tip for the future, sunscreen would be it.';
$blob = Crypto::seal($key, $nonce, $pt); // nonce || tag || ciphertext
$ct = substr($blob, Crypto::NONCE_SIZE + Crypto::TAG_SIZE);
$tag = substr($blob, Crypto::NONCE_SIZE, Crypto::TAG_SIZE);
check(
    'aead ciphertext rfc8439 2.8.2',
    bin2hex(substr($ct, 0, 16)),
    'd31a8d34648e60db7b86afbc53ef7ec2'
);
check('aead tag (empty AAD)', bin2hex($tag), '6a23a4681fd59456aea1d29f82477216');

// AEAD round-trip + tamper detection.
check('aead roundtrip', Crypto::open($key, $blob), $pt);
$tampered = $blob;
$tampered[28] = chr(ord($tampered[28]) ^ 1);
$threw = false;
try {
    Crypto::open($key, $tampered);
} catch (\Throwable $e) {
    $threw = true;
}
check('aead tamper detected', $threw ? 'yes' : 'no', 'yes');

// Protocol: request and response derive to unrelated addresses (unlinkable).
$secret = str_repeat("\x42", 32);
$reqAddr = Protocol::slotAddress($secret, Protocol::REQUEST, 0);
$resAddr = Protocol::slotAddress($secret, Protocol::RESPONSE, 0);
check('addr is 64-hex', (string) preg_match('/^[0-9a-f]{64}$/', $reqAddr), '1');
check('request != response address', $reqAddr === $resAddr ? 'same' : 'differ', 'differ');

echo $failures ? "\n$failures FAILURE(S)\n" : "\nall vectors pass\n";
exit($failures ? 1 : 0);
