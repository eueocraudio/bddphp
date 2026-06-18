<?php

declare(strict_types=1);

namespace Bdd\Tests;

use Bdd\Crypto;
use Bdd\Responder;
use Bdd\Server;
use Bdd\Store;
use PHPUnit\Framework\TestCase;

/**
 * Server routing/semantics exercised directly through Server::handle() with a
 * capturing Responder and a filesystem-backed Store — no HTTP context, no DB.
 */
final class ServerTest extends TestCase
{
    private Server $server;
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/bddphp_srv_' . bin2hex(random_bytes(6));
        $this->server = new Server(new Store($this->dir));
    }

    protected function tearDown(): void
    {
        if (!is_dir($this->dir)) {
            return;
        }
        foreach (scandir($this->dir) ?: [] as $f) {
            if ($f !== '.' && $f !== '..') {
                @unlink($this->dir . '/' . $f);
            }
        }
        @rmdir($this->dir);
    }

    /** @return array{0:int,1:Responder} */
    private function call(string $method, string $path, array $query = [], string $body = ''): array
    {
        $out = new Responder(capture: true);
        $status = $this->server->handle($method, $path, $query, $body, $out);
        return [$status, $out];
    }

    private function addr(string $seed): string
    {
        return hash('sha256', $seed);
    }

    public function testHealth(): void
    {
        [$status, $out] = $this->call('GET', '/v1/health');
        self::assertSame(200, $status);
        self::assertSame('application/json', $out->contentType);
        $json = json_decode($out->body, true);
        self::assertSame('ok', $json['status']);
        self::assertSame(Server::TTL_BUCKETS, $json['ttl_buckets']);
    }

    public function testPutGetDeleteRoundTrip(): void
    {
        $a = $this->addr('rt');
        [$put] = $this->call('PUT', "/v1/slot/$a", [], 'payload');
        self::assertSame(201, $put);

        [$get, $out] = $this->call('GET', "/v1/slot/$a");
        self::assertSame(200, $get);
        self::assertSame('payload', $out->body);

        [$del] = $this->call('DELETE', "/v1/slot/$a");
        self::assertSame(204, $del);

        [$gone] = $this->call('GET', "/v1/slot/$a");
        self::assertSame(404, $gone);
    }

    public function testWriteOnceReturns409(): void
    {
        $a = $this->addr('wo');
        self::assertSame(201, $this->call('PUT', "/v1/slot/$a", [], 'one')[0]);
        self::assertSame(409, $this->call('PUT', "/v1/slot/$a", [], 'two')[0]);
    }

    public function testMissingSlotIs404(): void
    {
        self::assertSame(404, $this->call('GET', '/v1/slot/' . $this->addr('x'))[0]);
    }

    public function testMalformedAddressIs404(): void
    {
        self::assertSame(404, $this->call('GET', '/v1/slot/xyz')[0]);
        self::assertSame(404, $this->call('GET', '/v1/slot/../etc/passwd')[0]);
    }

    public function testEmptyBodyIs413(): void
    {
        self::assertSame(413, $this->call('PUT', '/v1/slot/' . $this->addr('e'), [], '')[0]);
    }

    public function testOversizedBodyIs413(): void
    {
        $big = str_repeat('x', Server::MAX_BLOB + 1);
        self::assertSame(413, $this->call('PUT', '/v1/slot/' . $this->addr('big'), [], $big)[0]);
    }

    public function testTtlIsSnappedToBucket(): void
    {
        // A 10-second request snaps up to the smallest bucket (300s), so the
        // entry is still readable well beyond 10s.
        $a = $this->addr('ttl');
        $this->call('PUT', "/v1/slot/$a", ['ttl' => '10'], 'x');
        self::assertSame(200, $this->call('GET', "/v1/slot/$a")[0]);
    }

    public function testSnapTtl(): void
    {
        self::assertSame(300, Server::snapTtl(1));
        self::assertSame(300, Server::snapTtl(300));
        self::assertSame(3600, Server::snapTtl(301));
        self::assertSame(604800, Server::snapTtl(999999999));
    }

    public function testResponseBodyIsOpaqueBlob(): void
    {
        // The server returns exactly the stored bytes; it never inspects them.
        $a = $this->addr('opaque');
        $blob = Crypto::seal(random_bytes(32), random_bytes(Crypto::NONCE_SIZE), 'secret');
        $this->call('PUT', "/v1/slot/$a", [], $blob);
        [$status, $out] = $this->call('GET', "/v1/slot/$a");
        self::assertSame(200, $status);
        self::assertSame($blob, $out->body);
        self::assertSame('application/octet-stream', $out->contentType);
    }
}
