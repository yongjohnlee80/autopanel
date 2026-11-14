-- 000006, undone.
DROP TABLE IF EXISTS api_token;
DROP TABLE IF EXISTS recovery_code;
ALTER TABLE app_user DROP COLUMN totp_last_step;
ALTER TABLE app_user DROP COLUMN totp;
ALTER TABLE app_user DROP COLUMN last_login_at;
ALTER TABLE app_user DROP COLUMN fail_count;
ALTER TABLE app_user DROP COLUMN locked_until;
ALTER TABLE app_user DROP COLUMN disabled_at;
ALTER TABLE app_user DROP COLUMN must_change;
ALTER TABLE app_user DROP COLUMN verifier;
ALTER TABLE app_user DROP COLUMN role;
