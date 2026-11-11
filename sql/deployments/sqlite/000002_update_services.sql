-- 000002: deployed services, and the outcome of a privileged action.

-- A deployed service: what was asked for. What is running is systemd's to say.
-- options is JSON: the template's validated option values.
CREATE TABLE IF NOT EXISTS service (
  name       TEXT PRIMARY KEY,
  template   TEXT NOT NULL,
  options    TEXT NOT NULL,
  state      TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  CHECK (name <> '' AND name = lower(name)),
  CHECK (state IN ('deploying', 'deployed', 'removing'))
);

-- A privileged action's entry is written before the action, with outcome
-- 'attempt', and set afterwards to 'ok' or the error's name. An entry that
-- still says 'attempt' is an action the core did not see finish. Every other
-- entry leaves it empty.
ALTER TABLE audit ADD COLUMN outcome TEXT NOT NULL DEFAULT '';
