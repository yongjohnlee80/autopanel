-- 000007, undone. The rules stay in the manager, as rules made elsewhere:
-- deleting a host's open ports because the store was rolled back would cut
-- its services off with nothing said.
DROP INDEX IF EXISTS firewall_rule_owner;
DROP TABLE IF EXISTS firewall_rule;
