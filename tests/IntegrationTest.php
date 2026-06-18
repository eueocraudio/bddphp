<?php

declare(strict_types=1);

namespace Bdd\Tests;

use Bdd\Client;
use Bdd\Protocol;
use PHPUnit\Framework\TestCase;

/**
 * End-to-end: a real php built-in server process + the curl Client, talking
 * over a local socket against a throwaway data directory. Proves the blind
 * round trip (request/response unlinkable parts) works across the wire.
 */
final class IntegrationTest extends TestCase
{
    /** @var resource|null */
    private $proc = null;
    private int $pid = 0;
    private int $port = 0;
    private string $dataDir = '';

    protected function setUp(): void
    {
        if (!function_exists('proc_open') || !function_exists('posix_kill')) {
            self::markTestSkipped('proc_open/posix required for live server tests');
        }
        $this->dataDir = sys_get_temp_dir() . '/bddphp_int_' . bin2hex(random_bytes(6));

        $this->port = random_int(20000, 40000);
        $router = dirname(__DIR__) . '/public/index.php';
        $env = [
            'BDDPHP_DATA_DIR' => $this->dataDir,
            // Several workers so a held long-poll request doesn't starve others.
            'PHP_CLI_SERVER_WORKERS' => '4',
            'PATH' => getenv('PATH') ?: '/usr/bin',
        ];
        // `exec setsid` makes php its own session/group leader at the tracked
        // pid, so tearDown can kill the whole group (master + workers) at once.
        // Output goes to /dev/null: unread pipes inherited by workers would
        // otherwise wedge proc_close at shutdown.
        $cmd = sprintf('exec setsid php -S 127.0.0.1:%d %s', $this->port, escapeshellarg($router));
        $devnull = ['file', '/dev/null', 'w'];
        $this->proc = proc_open($cmd, [STDIN, $devnull, $devnull], $pipes, null, $env);
        self::assertIsResource($this->proc, 'failed to start server');
        $this->pid = (int) proc_get_status($this->proc)['pid'];
        $this->waitForServer();
    }

    protected function tearDown(): void
    {
        if ($this->pid > 0) {
            posix_kill(-$this->pid, SIGKILL); // kill the process group (workers too)
        }
        if (is_resource($this->proc)) {
            proc_close($this->proc);
        }
        if ($this->dataDir !== '' && is_dir($this->dataDir)) {
            foreach (scandir($this->dataDir) ?: [] as $f) {
                if ($f !== '.' && $f !== '..') {
                    @unlink($this->dataDir . '/' . $f);
                }
            }
            @rmdir($this->dataDir);
        }
    }

    private function waitForServer(): void
    {
        for ($i = 0; $i < 100; $i++) {
            $fp = @fsockopen('127.0.0.1', $this->port, $errno, $errstr, 0.1);
            if ($fp !== false) {
                fclose($fp);
                return;
            }
            usleep(50_000);
        }
        self::fail('server did not come up');
    }

    private function client(string $secret): Client
    {
        return new Client($secret, '127.0.0.1', $this->port, 'http');
    }

    public function testRequestResponseRoundTrip(): void
    {
        $secret = random_bytes(Protocol::SECRET_SIZE);
        $client = $this->client($secret);

        self::assertSame(201, $client->send(Protocol::REQUEST, 0, 'ping?'));
        self::assertSame(201, $client->send(Protocol::RESPONSE, 0, 'pong!'));

        self::assertSame('ping?', $client->receive(Protocol::REQUEST, 0));
        self::assertSame('pong!', $client->receive(Protocol::RESPONSE, 0));
    }

    public function testWrongSecretCannotDecryptOrLocate(): void
    {
        $secret = random_bytes(Protocol::SECRET_SIZE);
        $this->client($secret)->send(Protocol::REQUEST, 0, 'hello');

        // A different secret derives a different address: nothing there.
        $other = $this->client(random_bytes(Protocol::SECRET_SIZE));
        self::assertNull($other->receive(Protocol::REQUEST, 0));
    }

    public function testWriteOnceAcrossTheWire(): void
    {
        $client = $this->client(random_bytes(Protocol::SECRET_SIZE));
        self::assertSame(201, $client->send(Protocol::REQUEST, 1, 'first'));
        self::assertSame(409, $client->send(Protocol::REQUEST, 1, 'second'));
    }

    public function testPurge(): void
    {
        $client = $this->client(random_bytes(Protocol::SECRET_SIZE));
        $client->send(Protocol::RESPONSE, 2, 'temp');
        self::assertSame('temp', $client->receive(Protocol::RESPONSE, 2));
        self::assertTrue($client->purge(Protocol::RESPONSE, 2));
        self::assertNull($client->receive(Protocol::RESPONSE, 2));
    }

    public function testLongPollWakesOnPut(): void
    {
        $secret = random_bytes(Protocol::SECRET_SIZE);
        // Writer in a separate process after a short delay.
        $writer = $this->client($secret);
        $start = microtime(true);

        // Schedule the write ~0.4s out via a background php one-liner.
        $hex = bin2hex($secret);
        $script = sprintf(
            'usleep(400000); $c = new Bdd\Client(hex2bin(%s),"127.0.0.1",%d,"http"); '
            . '$c->send(Bdd\Protocol::RESPONSE, 5, "late");',
            var_export($hex, true),
            $this->port,
        );
        $boot = dirname(__DIR__) . '/src/autoload.php';
        $cmd = sprintf('php -r %s', escapeshellarg(sprintf('require %s; %s', var_export($boot, true), $script)));
        $bg = proc_open($cmd, [STDIN, STDOUT, STDERR], $p);

        $reader = $this->client($secret);
        $msg = $reader->receive(Protocol::RESPONSE, 5, 5.0); // long-poll up to 5s
        $elapsed = microtime(true) - $start;

        if (is_resource($bg)) {
            proc_close($bg);
        }
        self::assertSame('late', $msg);
        self::assertLessThan(5.0, $elapsed, 'long poll should wake before the cap');
    }
}
