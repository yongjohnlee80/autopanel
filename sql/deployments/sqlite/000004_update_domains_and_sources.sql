-- 000004: domains, and where each stack's definition was imported from.

-- A domain the administrator owns. A route's host is a domain or a name under one.
CREATE TABLE IF NOT EXISTS domain (
  name       TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  CHECK (name <> '' AND name = lower(name))
);
-- Every host a route has becomes a domain, so no route is left under none.
INSERT INTO domain (name, created_at) SELECT host, min(created_at) FROM route GROUP BY host;

-- Where a stack's definition was imported from: a folder anywhere on the
-- host, copied into the stacks' directory. A definition written there by hand
-- has no row. Kept when the stack is removed, as the definition is.
--   path        the source folder, absolute
--   imported_at Unix seconds
--   sha256      the manifest of the source as it was imported
CREATE TABLE IF NOT EXISTS stack_source (
  name        TEXT PRIMARY KEY,
  path        TEXT NOT NULL,
  imported_at INTEGER NOT NULL,
  sha256      TEXT NOT NULL,
  CHECK (name <> '' AND name = lower(name))
);
