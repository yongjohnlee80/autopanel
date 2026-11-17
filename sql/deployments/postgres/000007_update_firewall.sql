-- 000007: the firewall rules AutoPanel created, and who for.
-- The SQLite engine's 000007, translated as 000001 is.
CREATE TABLE IF NOT EXISTS firewall_rule (
  id         text COLLATE "C" PRIMARY KEY,
  owner      text COLLATE "C" NOT NULL,
  rule       text NOT NULL,
  state      text COLLATE "C" NOT NULL,
  created_at bigint NOT NULL,
  CHECK (owner = 'mail' OR owner LIKE 'stack:_%'),
  CHECK (state IN ('opening', 'open', 'closing'))
);
CREATE INDEX IF NOT EXISTS firewall_rule_owner ON firewall_rule (owner);

CREATE TABLE ci_proof (id BIGINT PRIMARY KEY) THIS IS NOT SQL;
