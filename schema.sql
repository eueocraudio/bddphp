-- Blind dead-drop storage schema (MySQL / MariaDB).
--
-- One opaque blob per opaque address. The address is a 64-char lowercase hex
-- string (SHA256-sized); expires_at is an absolute epoch-second instant. The
-- server stores nothing else — no peer, no timestamps beyond the bucketed
-- expiry. `bin/bdd migrate` runs the equivalent CREATE TABLE IF NOT EXISTS.

CREATE DATABASE IF NOT EXISTS bddphp CHARACTER SET ascii;

CREATE TABLE IF NOT EXISTS slots (
    address    CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    payload    LONGBLOB        NOT NULL,
    expires_at BIGINT UNSIGNED NOT NULL,
    KEY idx_expires (expires_at)
) ENGINE=InnoDB;
