-- 000004: domains, and where each stack's definition was imported from. The
-- SQLite engine's 000004, translated as 000001 is.

CREATE TABLE IF NOT EXISTS domain (
  name       text COLLATE "C" PRIMARY KEY,
  created_at bigint NOT NULL,
  CHECK (name <> '' AND name = lower(name))
);
INSERT INTO domain (name, created_at) SELECT host, min(created_at) FROM route GROUP BY host;

CREATE TABLE IF NOT EXISTS stack_source (
  name        text COLLATE "C" PRIMARY KEY,
  path        text COLLATE "C" NOT NULL,
  imported_at bigint NOT NULL,
  sha256      text COLLATE "C" NOT NULL,
  CHECK (name <> '' AND name = lower(name))
);
