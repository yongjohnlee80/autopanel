-- 000002: deployed services, and the outcome of a privileged action. The
-- SQLite engine's 000002, translated as 000001 is.

CREATE TABLE IF NOT EXISTS service (
  name       text COLLATE "C" PRIMARY KEY,
  template   text COLLATE "C" NOT NULL,
  options    text COLLATE "C" NOT NULL,
  state      text COLLATE "C" NOT NULL,
  created_at bigint NOT NULL,
  updated_at bigint NOT NULL,
  CHECK (name <> '' AND name = lower(name)),
  CHECK (state IN ('deploying', 'deployed', 'removing'))
);

ALTER TABLE audit ADD COLUMN outcome text COLLATE "C" NOT NULL DEFAULT '';
