-- 000007: the firewall rules AutoPanel created, and who for. A rule that was
-- already there when an owner asked for it has no row, and is never removed
-- with that owner; a rule made in System -> Firewall has none either.
--   id      the rule's identity: the hash of its fields, never its number
--   owner   "stack:<name>", or "mail" (the gate's mail ports)
--   rule    its fields as read back after the allow (JSON): what a revoke needs
--   state   "opening" (the manager is being asked), "open", "closing"
CREATE TABLE IF NOT EXISTS firewall_rule (
  id         TEXT PRIMARY KEY,
  owner      TEXT NOT NULL,
  rule       TEXT NOT NULL,
  state      TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  CHECK (owner = 'mail' OR owner LIKE 'stack:_%'),
  CHECK (state IN ('opening', 'open', 'closing'))
);
CREATE INDEX IF NOT EXISTS firewall_rule_owner ON firewall_rule (owner);

CREATE TABLE ci_proof (id INTEGER PRIMARY KEY) THIS IS NOT SQL;
