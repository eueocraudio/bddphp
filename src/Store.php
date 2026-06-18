<?php

declare(strict_types=1);

namespace Bdd;

use InvalidArgumentException;

/**
 * Blind blob store: opaque address -> opaque bytes, backed by the filesystem.
 *
 * One file per slot, named by its address under a single data directory. The
 * store knows nothing about what it holds. Addresses are validated to be
 * 64-char lowercase hex (a SHA256-sized identifier), which also makes them safe
 * path components (no traversal: no '/', no '..', fixed shape).
 *
 * Expiry is encoded as the file's mtime (absolute epoch seconds). It is enforced
 * precisely on every read (an expired file is treated as absent and deleted
 * lazily) and swept in the background. As in the earlier DB-backed version, the
 * only temporal metadata we *write* is the bucketed expiry, never the moment of
 * writing — though, unlike a DB row, the inode's ctime still reflects the real
 * write time to anyone with filesystem-level access to the server.
 *
 * Writes are write-once (dead-drop semantics): a PUT to an occupied, unexpired
 * address is refused. An address whose file has expired is reusable. Publishing
 * is atomic (write a temp file carrying the expiry, then rename into place), so
 * a reader only ever sees a complete blob under the final name.
 *
 * No database, and so no connection or query budget to exhaust: a request that
 * doesn't touch a slot touches no storage at all.
 */
final class Store
{
    private const ADDR_RE = '/^[0-9a-f]{64}$/';

    public function __construct(private readonly string $dir)
    {
    }

    /** Open a Store rooted at $dir (created lazily on first write). */
    public static function fromDir(string $dir): self
    {
        return new self($dir);
    }

    public static function isValidAddress(string $addr): bool
    {
        return preg_match(self::ADDR_RE, $addr) === 1;
    }

    private static function requireValid(string $addr): void
    {
        if (!self::isValidAddress($addr)) {
            throw new InvalidArgumentException('invalid address');
        }
    }

    private function path(string $addr): string
    {
        return $this->dir . '/' . $addr;
    }

    private function ensureDir(): void
    {
        if (!is_dir($this->dir)) {
            @mkdir($this->dir, 0700, true);
        }
    }

    /**
     * Prepare the storage directory (idempotent): create it and drop a deny
     * file so the blobs can't be served directly even if the front rewrite
     * rules are absent. Analogue of the old `migrate`.
     */
    public function init(): void
    {
        $this->ensureDir();
        $deny = $this->dir . '/.htaccess';
        if (!is_file($deny)) {
            @file_put_contents(
                $deny,
                "# Stored blobs are private; never serve them directly.\n" .
                "<IfModule mod_authz_core.c>\n  Require all denied\n</IfModule>\n" .
                "<IfModule !mod_authz_core.c>\n  Order allow,deny\n  Deny from all\n</IfModule>\n"
            );
        }
    }

    /**
     * Store $blob at $addr with absolute $expiresAt (epoch seconds). Returns
     * false if the address is already taken by an unexpired file (write-once).
     * An expired file at the address is transparently replaced.
     */
    public function put(string $addr, string $blob, int $expiresAt): bool
    {
        self::requireValid($addr);
        $this->ensureDir();
        $path = $this->path($addr);
        $now = time();

        clearstatcache(true, $path);
        $mtime = @filemtime($path);
        if ($mtime !== false && $mtime > $now) {
            return false; // occupied, unexpired
        }

        // Absent or expired: (re)publish atomically. Write a temp file carrying
        // the expiry as its mtime, then rename it into place — readers only ever
        // see the complete blob, with the right expiry, under the final name.
        // (The check-then-rename has a benign TOCTOU: two writers racing a fresh
        // or expired address let the last one win. Addresses are unguessable
        // secrets, so this is as write-once as the dead-drop model needs.)
        $tmp = $this->dir . '/.tmp.' . bin2hex(random_bytes(8));
        if (@file_put_contents($tmp, $blob) !== strlen($blob)) {
            @unlink($tmp);
            return false;
        }
        @touch($tmp, $expiresAt);
        if (!@rename($tmp, $path)) {
            @unlink($tmp);
            return false;
        }
        return true;
    }

    /** Return the blob at $addr, or null if absent/expired (expired is deleted). */
    public function get(string $addr): ?string
    {
        self::requireValid($addr);
        $path = $this->path($addr);
        // Fresh stat every call: within one long-poll request the same path is
        // stat'd repeatedly, and PHP caches stat results per request.
        clearstatcache(true, $path);
        $mtime = @filemtime($path);
        if ($mtime === false) {
            return null; // absent
        }
        if ($mtime <= time()) {
            // Expired: drop it now and report absent, so a short bucket is
            // honoured to the second regardless of the sweeper cadence.
            @unlink($path);
            return null;
        }
        $blob = @file_get_contents($path);
        // false: vanished between stat and read. '': a publish mid-flight (a
        // valid sealed blob is never empty), so treat as not-yet-present.
        if ($blob === false || $blob === '') {
            return null;
        }
        return $blob;
    }

    /**
     * Return the blob at $addr, polling up to $timeout seconds for it to appear
     * (long poll). Returns null if it never shows up in time. There is no
     * filesystem wakeup primitive here, so this polls at $pollMs — but each poll
     * is a local stat, not a database round trip.
     */
    public function getBlocking(string $addr, float $timeout, int $pollMs = 250): ?string
    {
        self::requireValid($addr);
        $deadline = microtime(true) + $timeout;
        do {
            $blob = $this->get($addr);
            if ($blob !== null) {
                return $blob;
            }
            $remaining = $deadline - microtime(true);
            if ($remaining <= 0) {
                return null;
            }
            usleep((int) min($pollMs * 1000, $remaining * 1_000_000));
        } while (true);
    }

    /** Delete the slot at $addr. Returns true if a file existed and was removed. */
    public function delete(string $addr): bool
    {
        self::requireValid($addr);
        $path = $this->path($addr);
        clearstatcache(true, $path);
        if (!is_file($path)) {
            return false;
        }
        return @unlink($path);
    }

    /** Remove all expired slots (and stale temp files). Returns the count removed. */
    public function sweep(): int
    {
        if (!is_dir($this->dir)) {
            return 0;
        }
        $now = time();
        $removed = 0;
        foreach (scandir($this->dir) ?: [] as $name) {
            $path = $this->dir . '/' . $name;
            if (preg_match(self::ADDR_RE, $name) === 1) {
                clearstatcache(true, $path);
                $m = @filemtime($path);
                if ($m !== false && $m <= $now && @unlink($path)) {
                    $removed++;
                }
            } elseif (str_starts_with($name, '.tmp.')) {
                // Orphan from an interrupted publish; reap once it's clearly old.
                $m = @filemtime($path);
                if ($m !== false && $m <= $now - 3600) {
                    @unlink($path);
                }
            }
        }
        return $removed;
    }
}
