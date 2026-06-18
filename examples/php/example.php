<?php

declare(strict_types=1);

// Blind Dead Drop — PHP example client (uses the bddphp package directly).
//
// This is the "native" client: it imports Bdd\Client from the package, so it
// shares the audited OpenSSL/hash_hkdf crypto with the server. (The Python and
// C++ examples reimplement the protocol from scratch to show the wire format is
// a cross-language contract.)
//
// Usage:
//   php example.php --secret HEX [--host H] [--port P] [--scheme http|https]
//                   [--insecure] [--cafile PATH] CMD CHANNEL [MSG]
//
// CMD: send-request | get-request | send-response | get-response |
//      wait-response | reply-upper
// The secret may also come from the BDD_SECRET environment variable.

require __DIR__ . '/../../src/autoload.php';

use Bdd\Client;

$host = '127.0.0.1';
$port = 8080;
$scheme = 'http';
$secretHex = getenv('BDD_SECRET') ?: '';
$insecure = false;
$cafile = '';
$pos = [];

$args = $argv;
array_shift($args);
for ($i = 0, $n = count($args); $i < $n; $i++) {
    $a = $args[$i];
    if ($a === '--host') {
        $host = $args[++$i];
    } elseif ($a === '--port') {
        $port = (int) $args[++$i];
    } elseif ($a === '--scheme') {
        $scheme = $args[++$i];
    } elseif ($a === '--secret') {
        $secretHex = $args[++$i];
    } elseif ($a === '--cafile') {
        $cafile = $args[++$i];
    } elseif ($a === '--insecure') {
        $insecure = true;
    } else {
        $pos[] = $a;
    }
}

if (count($pos) < 1 || strlen($secretHex) !== 64) {
    fwrite(STDERR, "usage: php example.php --secret HEX [--host H --port P "
        . "--scheme http|https --insecure --cafile PATH] CMD CHANNEL [MSG]\n");
    exit(64);
}

$secret = (string) hex2bin($secretHex);
$cmd = $pos[0];
$channel = isset($pos[1]) ? (int) $pos[1] : 0;
$msg = $pos[2] ?? '';

$client = new Client($secret, $host, $port, $scheme, $insecure, $cafile);

$status = static function (int $code): int {
    if ($code === 201) {
        fwrite(STDERR, "ok: stored\n");
        return 0;
    }
    if ($code === 409) {
        fwrite(STDERR, "error: slot already used\n");
        return 2;
    }
    fwrite(STDERR, "error: server returned $code\n");
    return 1;
};

$show = static function (?string $pt): int {
    if ($pt === null) {
        fwrite(STDERR, "error: no message\n");
        return 2;
    }
    fwrite(STDOUT, $pt . "\n");
    return 0;
};

switch ($cmd) {
    case 'send-request':  exit($status($client->send('request', $channel, $msg)));
    case 'send-response': exit($status($client->send('response', $channel, $msg)));
    case 'get-request':   exit($show($client->receive('request', $channel)));
    case 'get-response':  exit($show($client->receive('response', $channel)));
    case 'wait-response': exit($show($client->receive('response', $channel, 30)));
    case 'reply-upper':
        // Worker role: wait for a request, process it (uppercase), respond.
        $req = $client->receive('request', $channel, 30);
        if ($req === null) {
            fwrite(STDERR, "error: no request arrived\n");
            exit(2);
        }
        $client->send('response', $channel, strtoupper($req));
        fwrite(STDERR, "replied to $req\n");
        exit(0);
    default:
        fwrite(STDERR, "unknown command: $cmd\n");
        exit(64);
}
