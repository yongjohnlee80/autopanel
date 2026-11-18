-- 000008, undone. The forwards go; the gate stops forwarding their ports at
-- its next table. A forward's firewall rule stays in the manager, as a rule
-- made elsewhere: its row goes, since an older AutoPanel knows no such owner.
DROP TABLE IF EXISTS forward;
DELETE FROM firewall_rule WHERE owner LIKE 'forward:%';
ALTER TABLE firewall_rule DROP CONSTRAINT IF EXISTS firewall_rule_owner_check;
ALTER TABLE firewall_rule ADD CONSTRAINT firewall_rule_owner_check
  CHECK (owner = 'mail' OR owner LIKE 'stack:_%');
