<?php

declare(strict_types=1);

namespace Bdd\Tests;

use Bdd\Store;
use PDO;
use PHPUnit\Framework\TestCase;

/**
 * Store behaviour against a real MySQL/MariaDB test database (configured via
 * BDDPHP_TEST_* env in phpunit.xml). Each test starts from an empty table.
 */
final class StoreTest extends TestCase
{
    private PDO $pdo;
    private Store $store;

    protected function setUp(): void
    {
        $dsn = getenv('BDDPHP_TEST_DSN');
        if ($dsn === false) {
            self::markTestSkipped('BDDPHP_TEST_DSN not set');
        }
        $this->pdo = new PDO(
            $dsn,
            (string) getenv('BDDPHP_TEST_USER'),
            (string) getenv('BDDPHP_TEST_PASS'),
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION],
        );
        $this->store = new Store($this->pdo);
        $this->store->migrate();
        $this->pdo->exec('TRUNCATE TABLE slots');
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
