-- 000003: stacks replace templated services.

-- A stack: what was applied. What is running is systemd's to say.
--   applied    JSON: the manifest of its definition, its unit files (each with
--              its image, the digest its pull resolved, its ports), and the
--              paths that are its data.
--   applied_at when the last apply finished, Unix seconds; 0 for none.
--   stopped    JSON: the services a person stopped. They stay stopped across a
--              boot.
--   pending    JSON: an apply that began and has not ended: everything the
--              stack had before with everything the apply may make. '' for none.
-- template and options stay, unused: a revert of this script must find a row
-- an older AutoPanel wrote whole.
ALTER TABLE service ADD COLUMN applied TEXT NOT NULL DEFAULT '';
ALTER TABLE service ADD COLUMN applied_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE service ADD COLUMN stopped TEXT NOT NULL DEFAULT '[]';
ALTER TABLE service ADD COLUMN pending TEXT NOT NULL DEFAULT '';
