<?php

declare(strict_types=1);

namespace Bdd;

use InvalidArgumentException;
use PDO;

/**
 * Blind blob store: opaque address -> opaque bytes, backed by MySQL.
 *
 * The store knows nothing about what it holds. Addresses are validated to be
 * 64-char lowercase hex (a SHA256-sized identifier), which also makes them safe
 * bound parameters (no injection, fixed shape).
 *
 * Each row carries an absolute expiry instant (`expires_at`, epoch seconds).
 * Expiry is enforced precisely on every read (an expired row is treated as
 * absent and deleted lazily) and swept in the background. The only temporal
 * metadata at rest is the (bucketed) expiry time, not the moment of writing.
 *
 * Writes are write-once (dead-drop semantics): a PUT to an occupied,
 * unexpired address is refused. An address whose row has expired is reusable.
 */
final class Store
{
    private const ADDR_RE = '/^[0-9a-f]{64}$/';

    public function __construct(private readonly PDO $pdo)
    {
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    }

    /** Open a Store from a DSN (e.g. "mysql:host=127.0.0.1;dbname=bddphp"). */
    public static function fromDsn(string $dsn, string $user, string $password): self
    {
        $pdo = new PDO($dsn, $user, $password, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
        return new self($pdo);
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

    /** Create the slots table if it does not exist (idempotent). */
    public function migrate(): void
    {
        $this->pdo->exec(
            'CREATE TABLE IF NOT EXISTS slots (' .
            '  address CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,' .
            '  payload LONGBLOB NOT NULL,' .
            '  expires_at BIGINT UNSIGNED NOT NULL,' .
            '  KEY idx_expires (expires_at)' .
            ') ENGINE=InnoDB'
        );
    }

    /**
     * Store $blob at $addr with absolute $expiresAt (epoch seconds). Returns
     * false if the address is already taken by an unexpired row (write-once).
     * An expired row at the address is transparently replaced.
     */
    public function put(string $addr, string $blob, int $expiresAt): bool
    {
        self::requireValid($addr);
        $now = time();
        $this->pdo->beginTransaction();
        try {
            $sel = $this->pdo->prepare(
                'SELECT expires_at FROM slots WHERE address = ? FOR UPDATE'
            );
            $sel->execute([$addr]);
            $row = $sel->fetch();
            if ($row !== false && (int) $row['expires_at'] > $now) {
                $this->pdo->commit();
                return false; // occupied
            }
            // Absent or expired: (re)publish. ON DUPLICATE handles the expired case.
            $up = $this->pdo->prepare(
                'INSERT INTO slots (address, payload, expires_at) VALUES (?, ?, ?) ' .
                'ON DUPLICATE KEY UPDATE payload = VALUES(payload), expires_at = VALUES(expires_at)'
            );
            $up->bindValue(1, $addr);
            $up->bindValue(2, $blob, PDO::PARAM_LOB);
            $up->bindValue(3, $expiresAt, PDO::PARAM_INT);
            $up->execute();
            $this->pdo->commit();
            return true;
        } catch (\Throwable $e) {
            $this->pdo->rollBack();
            throw $e;
        }
    }

    /** Return the blob at $addr, or null if absent/expired (expired is deleted). */
    public function get(string $addr): ?string
    {
        self::requireValid($addr);
        $sel = $this->pdo->prepare('SELECT payload, expires_at FROM slots WHERE address = ?');
        $sel->execute([$addr]);
        $row = $sel->fetch();
        if ($row === false) {
            return null;
        }
        if ((int) $row['expires_at'] <= time()) {
            // Expired: drop it now and report absent, so a short bucket is
            // honoured to the second regardless of the sweeper cadence.
            $this->delete($addr);
            return null;
        }
        $payload = $row['payload'];
        // PDO may hand a LOB back as a stream depending on driver settings.
        return is_resource($payload) ? (string) stream_get_contents($payload) : (string) $payload;
    }

    /**
     * Return the blob at $addr, polling up to $timeout seconds for it to appear
     * (long poll). Returns null if it never shows up in time. MySQL has no
     * cross-connection blocking primitive here, so this polls at $pollMs.
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

    /** Delete the slot at $addr. Returns true if a row existed. */
    public function delete(string $addr): bool
    {
        self::requireValid($addr);
        $del = $this->pdo->prepare('DELETE FROM slots WHERE address = ?');
        $del->execute([$addr]);
        return $del->rowCount() > 0;
    }

    /** Remove all expired rows. Returns the count removed. */
    public function sweep(): int
    {
        $del = $this->pdo->prepare('DELETE FROM slots WHERE expires_at <= ?');
        $del->execute([time()]);
        return $del->rowCount();
    }
}
