-- 000009: tunnel agents. An agent is a machine with no open port that dials
-- the gate and holds a tunnel open; it is known by its public key.
--   name           its name, for the panel, the log and tunnel://<name>/…
--   pubkey         the SHA-256 of its public key, in hex; '' until it enrols
--   enrolled_from  the address it enrolled from, for the administrator to check
--   token_id, token_hash, token_expires
--                  the one-time enrolment token while the agent has not
--                  enrolled: its id, the SHA-256 of its secret, and its end.
--                  The secret itself is never stored.
-- An agent is either waiting to enrol or enrolled, never both.
CREATE TABLE IF NOT EXISTS tunnel_agent (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  name          TEXT NOT NULL UNIQUE,
  pubkey        TEXT NOT NULL DEFAULT '',
  enrolled_from TEXT NOT NULL DEFAULT '',
  enrolled_at   INTEGER NOT NULL DEFAULT 0,
  token_id      TEXT NOT NULL DEFAULT '',
  token_hash    TEXT NOT NULL DEFAULT '',
  token_expires INTEGER NOT NULL DEFAULT 0,
  created_at    INTEGER NOT NULL,
  CHECK (name <> '' AND name = lower(name)),
  CHECK (pubkey = '' OR length(pubkey) = 64),
  CHECK ((pubkey = '') <> (token_id = ''))
);
-- One key is one agent.
CREATE UNIQUE INDEX IF NOT EXISTS tunnel_agent_pubkey ON tunnel_agent(pubkey) WHERE pubkey <> '';
CREATE UNIQUE INDEX IF NOT EXISTS tunnel_agent_token ON tunnel_agent(token_id) WHERE token_id <> '';
