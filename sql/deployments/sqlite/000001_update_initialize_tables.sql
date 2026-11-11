-- 000001: AutoPanel's store. The settings, the routes the gate serves, the
-- audit log, CertMagic's key space, the users and the keyslots that hold the
-- master key, the sealed secrets, and the lease that keeps one AutoPanel per
-- store.
--
-- The baseline has no revert: undoing it would drop the store. The ledger of
-- applied scripts (schema_version) is golib dao/deploy's, created by it.
-- Until the first tagged release this script may still change; from then on a
-- released script never changes.

-- A panel setting, by key. Values are text; the module that owns a key parses it.
CREATE TABLE IF NOT EXISTS setting (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

-- A route: requests for host whose path starts with path_prefix go to upstream.
-- host is canonical (lower case, no port, no trailing dot), so the unique key
-- is the one the gate matches on.
CREATE TABLE IF NOT EXISTS route (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  host        TEXT NOT NULL,
  path_prefix TEXT NOT NULL DEFAULT '/',
  upstream    TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL,
  UNIQUE (host, path_prefix),
  CHECK (host <> '' AND host = lower(host)),
  CHECK (substr(path_prefix, 1, 1) = '/')
);

-- One audit row per change, written in the change's own transaction. actor is
-- who asked (a user, or "local:<uid>" on the control socket).
CREATE TABLE IF NOT EXISTS audit (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  at      INTEGER NOT NULL,
  actor   TEXT NOT NULL,
  action  TEXT NOT NULL,
  subject TEXT NOT NULL,
  detail  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS audit_at ON audit (at, id);

-- CertMagic's key space: certificates, their private keys, ACME account keys.
-- Every value is sealed under the master key (AES-256-GCM, AAD naming its key).
CREATE TABLE IF NOT EXISTS cert_blob (
  key         TEXT PRIMARY KEY,
  value       BLOB NOT NULL,
  modified_at INTEGER NOT NULL
);

-- The store's one holder. A second AutoPanel on the same store finds the row
-- held and refuses to start (ADR: one AutoPanel per store).
CREATE TABLE IF NOT EXISTS store_lease (
  id         INTEGER PRIMARY KEY CHECK (id = 1),
  holder     TEXT NOT NULL,
  started_at INTEGER NOT NULL,
  renewed_at INTEGER NOT NULL
);

-- A panel user. The first, made by --init, is root.
CREATE TABLE IF NOT EXISTS app_user (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  name       TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  CHECK (name <> '')
);

-- A wrapped copy of the master key. A passphrase slot belongs to a user and is
-- also that user's login; the service slot (no user) opens with the keyfile.
-- slot is the keyslot package's JSON: salt, cost parameters, digest, ciphertext.
CREATE TABLE IF NOT EXISTS keyslot (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  kind       TEXT NOT NULL,
  user_id    INTEGER REFERENCES app_user(id) ON DELETE CASCADE,
  slot       TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  CHECK (kind IN ('passphrase', 'service')),
  CHECK ((kind = 'passphrase') = (user_id IS NOT NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS keyslot_passphrase_user ON keyslot (user_id) WHERE kind = 'passphrase';
CREATE UNIQUE INDEX IF NOT EXISTS keyslot_one_service ON keyslot (kind) WHERE kind = 'service';

-- A secret the panel keeps (the Cloudflare API token), sealed under the master
-- key with AAD naming it.
CREATE TABLE IF NOT EXISTS secret (
  name       TEXT PRIMARY KEY,
  value      BLOB NOT NULL,
  updated_at INTEGER NOT NULL
);
