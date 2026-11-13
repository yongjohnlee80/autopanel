-- 000003: stacks replace templated services. The SQLite engine's 000003,
-- translated as 000001 is.

ALTER TABLE service ADD COLUMN applied text COLLATE "C" NOT NULL DEFAULT '';
ALTER TABLE service ADD COLUMN applied_at bigint NOT NULL DEFAULT 0;
ALTER TABLE service ADD COLUMN stopped text COLLATE "C" NOT NULL DEFAULT '[]';
ALTER TABLE service ADD COLUMN pending text COLLATE "C" NOT NULL DEFAULT '';
