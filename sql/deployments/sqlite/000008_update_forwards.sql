-- 000008: port forwards. A forward sends a public port (or a range) of the
-- host on to a target, through the gate.
--   name        its name, for the panel, the log and its firewall rule's owner
--   proto       tcp or udp
--   port_from, port_to   the public port, or a range; equal for one port
--   target      a literal address and port; a range keeps its ports from there
--   proxy       1: each connection starts with a PROXY v2 header naming the client
--   allow       source prefixes that may connect, separated by spaces; '' is any
--   per_client, idle_secs   0: the default
CREATE TABLE IF NOT EXISTS forward (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  name       TEXT NOT NULL UNIQUE,
  proto      TEXT NOT NULL,
  port_from  INTEGER NOT NULL,
  port_to    INTEGER NOT NULL,
  target     TEXT NOT NULL,
  proxy      INTEGER NOT NULL DEFAULT 0,
  allow      TEXT NOT NULL DEFAULT '',
  per_client INTEGER NOT NULL DEFAULT 0,
  idle_secs  INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  CHECK (name <> '' AND name = lower(name)),
  CHECK (proto IN ('tcp', 'udp')),
  CHECK (port_from BETWEEN 1 AND 65535 AND port_to BETWEEN port_from AND 65535),
  CHECK (target <> ''),
  CHECK (proxy IN (0, 1))
);

-- A forward owns the firewall rule of its port, as a stack and mail own
-- theirs: the owner may now be "forward:<name>". SQLite cannot change a
-- table's CHECK, so the table is made again with its rows.
DROP TABLE IF EXISTS firewall_rule_new;
CREATE TABLE firewall_rule_new (
  id         TEXT PRIMARY KEY,
  owner      TEXT NOT NULL,
  rule       TEXT NOT NULL,
  state      TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  CHECK (owner = 'mail' OR owner LIKE 'stack:_%' OR owner LIKE 'forward:_%'),
  CHECK (state IN ('opening', 'open', 'closing'))
);
INSERT INTO firewall_rule_new (id, owner, rule, state, created_at) SELECT id, owner, rule, state, created_at FROM firewall_rule;
DROP TABLE firewall_rule;
ALTER TABLE firewall_rule_new RENAME TO firewall_rule;
CREATE INDEX IF NOT EXISTS firewall_rule_owner ON firewall_rule (owner);
