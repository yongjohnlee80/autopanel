-- 000003, undone.
ALTER TABLE service DROP COLUMN pending;
ALTER TABLE service DROP COLUMN stopped;
ALTER TABLE service DROP COLUMN applied_at;
ALTER TABLE service DROP COLUMN applied;
