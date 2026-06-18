<?php

declare(strict_types=1);

namespace Bdd\Tests;

use Bdd\Store;
use PHPUnit\Framework\TestCase;

/**
 * Store behaviour against a throwaway filesystem directory. No database, so no
 * configuration or skips: each test starts from an empty, private temp dir.
 */
final class StoreTest extends TestCase
{
    private string $dir;
    private Store $store;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/bddphp_store_' . bin2hex(random_bytes(6));
        $this->store = new Store($this->dir);
    }

    protected function tearDown(): void
    {
        self::rmrf($this->dir);
    }

    private static function rmrf(string $d): void
    {
        if (!is_dir($d)) {
            return;
        }
        foreach (scandir($d) ?: [] as $f) {
            if ($f === '.' || $f === '..') {
                continue;
            }
            $p = "$d/$f";
            is_dir($p) ? self::rmrf($p) : @unlink($p);
        }
        @rmdir($d);
    }

    private function addr(string $seed): string
    {
        return hash('sha256', $seed);
    }

    public function testPutThenGet(): void
    {
        $a = $this->addr('a');
        self::assertTrue($this->store->put($a, 'blob', time() + 60));
        self::assertSame('blob', $this->store->get($a));
    }

    public function testBinarySafe(): void
    {
        $a = $this->addr('bin');
        $blob = random_bytes(1024) . "\x00\xff\x00";
        $this->store->put($a, $blob, time() + 60);
        self::assertSame($blob, $this->store->get($a));
    }

    public function testWriteOnce(): void
    {
        $a = $this->addr('once');
        self::assertTrue($this->store->put($a, 'first', time() + 60));
        self::assertFalse($this->store->put($a, 'second', time() + 60));
        self::assertSame('first', $this->store->get($a));
    }

    public function testExpiredSlotIsAbsentAndReusable(): void
    {
        $a = $this->addr('exp');
        self::assertTrue($this->store->put($a, 'old', time() - 1)); // already expired
        self::assertNull($this->store->get($a)); // lazy-deleted on read
        self::assertTrue($this->store->put($a, 'new', time() + 60)); // address freed
        self::assertSame('new', $this->store->get($a));
    }

    public function testGetMissingReturnsNull(): void
    {
        self::assertNull($this->store->get($this->addr('missing')));
    }

    public function testDelete(): void
    {
        $a = $this->addr('del');
        $this->store->put($a, 'x', time() + 60);
        self::assertTrue($this->store->delete($a));
        self::assertFalse($this->store->delete($a));
        self::assertNull($this->store->get($a));
    }

    public function testSweepRemovesOnlyExpired(): void
    {
        $this->store->put($this->addr('live'), 'x', time() + 60);
        $this->store->put($this->addr('dead'), 'y', time() - 1);
        self::assertSame(1, $this->store->sweep());
        self::assertSame('x', $this->store->get($this->addr('live')));
    }

    public function testInvalidAddressRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->store->put('not-a-valid-address', 'x', time() + 60);
    }

    public function testGetBlockingTimesOut(): void
    {
        $start = microtime(true);
        self::assertNull($this->store->getBlocking($this->addr('never'), 0.3, 50));
        self::assertGreaterThanOrEqual(0.3, microtime(true) - $start);
    }
}
