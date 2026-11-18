-- 000008, undone. The forwards go; the gate stops forwarding their ports at
-- its next table. A forward's firewall rule stays in the manager, as a rule
-- made elsewhere: its row goes, since an older AutoPanel knows no such owner.
DROP TABLE IF EXISTS forward;
DELETE FROM firewall_rule WHERE owner LIKE 'forward:%';
DROP TABLE IF EXISTS firewall_rule_old;
CREATE TABLE firewall_rule_old (
  id         TEXT PRIMARY KEY,
  owner      TEXT NOT NULL,
  rule       TEXT NOT NULL,
  state      TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  CHECK (owner = 'mail' OR owner LIKE 'stack:_%'),
  CHECK (state IN ('opening', 'open', 'closing'))
);
INSERT INTO firewall_rule_old (id, owner, rule, state, created_at) SELECT id, owner, rule, state, created_at FROM firewall_rule;
DROP TABLE firewall_rule;
ALTER TABLE firewall_rule_old RENAME TO firewall_rule;
CREATE INDEX IF NOT EXISTS firewall_rule_owner ON firewall_rule (owner);
