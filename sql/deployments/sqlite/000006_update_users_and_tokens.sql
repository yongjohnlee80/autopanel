-- 000006: users with roles, their second factor, the lockout, and API tokens.

-- A user's role, and how it logs in. An admin logs in with its passphrase
-- slot, which holds the master key; any other role with an argon2id verifier
-- (verifier), which opens nothing. The store keeps the two apart.
--   must_change     1: the next login must change the passphrase (an admin reset it)
--   disabled_at     Unix seconds; 0 while enabled
--   locked_until    Unix seconds: a run of failed logins locked it until then
--   fail_count      failed logins in a row
--   totp            1: the second factor is enrolled (its seed is a secret, sealed)
--   totp_last_step  the last accepted TOTP step: a code is accepted once
ALTER TABLE app_user ADD COLUMN role TEXT NOT NULL DEFAULT 'admin';
ALTER TABLE app_user ADD COLUMN verifier TEXT NOT NULL DEFAULT '';
ALTER TABLE app_user ADD COLUMN must_change INTEGER NOT NULL DEFAULT 0;
ALTER TABLE app_user ADD COLUMN disabled_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE app_user ADD COLUMN locked_until INTEGER NOT NULL DEFAULT 0;
ALTER TABLE app_user ADD COLUMN fail_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE app_user ADD COLUMN last_login_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE app_user ADD COLUMN totp INTEGER NOT NULL DEFAULT 0;
ALTER TABLE app_user ADD COLUMN totp_last_step INTEGER NOT NULL DEFAULT 0;

-- A user's unused recovery codes, by their SHA-256: each opens one login.
CREATE TABLE IF NOT EXISTS recovery_code (
  user_id INTEGER NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  hash    BLOB NOT NULL,
  PRIMARY KEY (user_id, hash)
);

-- An API token: the CLI's and a script's login. Its secret is kept as its
-- SHA-256, shown once when made. Its role is no higher than its owner's.
CREATE TABLE IF NOT EXISTS api_token (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id      INTEGER NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  name         TEXT NOT NULL,
  hash         BLOB NOT NULL UNIQUE,
  role         TEXT NOT NULL,
  created_at   INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,
  last_used_at INTEGER NOT NULL DEFAULT 0,
  revoked_at   INTEGER NOT NULL DEFAULT 0,
  CHECK (name <> ''),
  CHECK (role IN ('admin', 'operator', 'mail', 'viewer'))
);
